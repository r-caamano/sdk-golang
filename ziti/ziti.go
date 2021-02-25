/*
	Copyright 2019 NetFoundry, Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package ziti

import (
	errors2 "errors"
	"fmt"
	"github.com/cenkalti/backoff/v4"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/foundation/identity/identity"
	"github.com/openziti/foundation/metrics"
	"github.com/openziti/foundation/util/concurrenz"
	"github.com/openziti/sdk-golang/ziti/config"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/openziti/sdk-golang/ziti/edge/api"
	"github.com/openziti/sdk-golang/ziti/edge/posture"
	"github.com/openziti/sdk-golang/ziti/sdkinfo"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"reflect"
	"sync"
	"time"
)

const (
	LatencyCheckInterval = 30 * time.Second
)

type Context interface {
	Authenticate() error
	GetClientIdentity() identity.Identity
	GetCurrentIdentity() (*edge.CurrentIdentity, error)
	GetCurrentApiSession() *edge.ApiSession
	Dial(serviceName string) (edge.Conn, error)
	DialWithOptions(serviceName string, options *DialOptions) (edge.Conn, error)
	Listen(serviceName string) (edge.Listener, error)
	ListenWithOptions(serviceName string, options *ListenOptions) (edge.Listener, error)
	GetServiceId(serviceName string) (string, bool, error)
	GetServices() ([]edge.Service, error)
	GetService(serviceName string) (*edge.Service, bool)
	RefreshSession(session *edge.Session) (*edge.Session, error)
	GetSession(id string) (*edge.Session, error)
	GetCloseNotify() <-chan struct{}

	Metrics() metrics.Registry
	// Close closes any connections open to edge routers
	Close()

	// Add a Ziti MFA handler, invoked during authentication
	AddZitiMfaHandler(handler func(query *edge.AuthQuery, resp func(code string) error) error)
	EnrollZitiMfa() (*api.MfaEnrollment, error)
	VerifyZitiMfa(code string) error
	RemoveZitiMfa(code string) error
}

type DialOptions struct {
	ConnectTimeout time.Duration
	Identity       string
	AppData        []byte
}

func (d DialOptions) GetConnectTimeout() time.Duration {
	return d.ConnectTimeout
}

type Precedence byte

func (p Precedence) String() string {
	if p == PrecedenceRequired {
		return PrecedenceRequiredLabel
	}
	if p == PrecedenceFailed {
		return PrecedenceFailedLabel
	}
	return PrecedenceDefaultLabel
}

const (
	PrecedenceDefault  Precedence = 0
	PrecedenceRequired            = 1
	PrecedenceFailed              = 2

	PrecedenceDefaultLabel  = "default"
	PrecedenceRequiredLabel = "required"
	PrecedenceFailedLabel   = "failed"
)

func GetPrecedenceForLabel(p string) Precedence {
	if p == PrecedenceRequiredLabel {
		return PrecedenceRequired
	}
	if p == PrecedenceFailedLabel {
		return PrecedenceFailed
	}
	return PrecedenceDefault
}

type ListenOptions struct {
	Cost                  uint16
	Precedence            Precedence
	ConnectTimeout        time.Duration
	MaxConnections        int
	Identity              string
	BindUsingEdgeIdentity bool
	ManualStart           bool
}

func DefaultListenOptions() *ListenOptions {
	return &ListenOptions{
		Cost:           0,
		Precedence:     PrecedenceDefault,
		ConnectTimeout: 5 * time.Second,
		MaxConnections: 3,
	}
}

var globalAppId = ""
var globalAppVersion = ""

//Set the `appId` and `appVersion` to provide in SDK Information during all Ziti context authentications
func SetAppInfo(appId, appVersion string) {
	globalAppId = appId
	globalAppVersion = appVersion
}

type contextImpl struct {
	options      *Options
	routerClient RouterClient

	ctrlClt api.Client

	services sync.Map // name -> Service
	sessions sync.Map // svcID:type -> Session

	metrics metrics.Registry

	firstAuthOnce sync.Once

	postureCache      *posture.Cache
	closed            concurrenz.AtomicBoolean
	closeNotify       chan struct{}
	authQueryHandlers map[string]func(query *edge.AuthQuery, resp func(code string) error) error
}

func NewContext() Context {
	return NewContextWithConfig(nil)
}

func NewContextWithConfig(cfg *config.Config) Context {
	return NewContextWithOpts(cfg, nil)
}

func NewContextWithOpts(cfg *config.Config, options *Options) Context {
	if options == nil {
		options = DefaultOptions
	}

	var routerClient RouterClient
	if options.RouterClient != nil {
		routerClient = options.RouterClient
	} else {
		routerClient = NewNetworkRouterClient()
	}

	result := &contextImpl{
		routerClient:      routerClient,
		options:           options,
		authQueryHandlers: map[string]func(query *edge.AuthQuery, resp func(code string) error) error{},
		closeNotify:       make(chan struct{}),
	}

	result.ctrlClt = api.NewLazyClient(cfg, func(ctrlClient api.Client) error {
		result.postureCache = posture.NewCache(ctrlClient, result.closeNotify)
		return nil
	})

	return result
}

func (context *contextImpl) initialize() error {
	return context.ctrlClt.Initialize()
}

func (context *contextImpl) GetClientIdentity() identity.Identity {
	return context.ctrlClt.GetIdentity()
}

func (context *contextImpl) GetCurrentApiSession() *edge.ApiSession {
	return context.ctrlClt.GetCurrentApiSession()
}

func (context *contextImpl) GetCloseNotify() <-chan struct{} {
	return context.closeNotify
}

func (context *contextImpl) processServiceUpdates(services []*edge.Service) {
	pfxlog.Logger().Debugf("procesing service updates with %v services", len(services))

	idMap := make(map[string]*edge.Service)
	for _, s := range services {
		idMap[s.Id] = s
	}

	// process Deletes
	var deletes []string
	context.services.Range(func(key, value interface{}) bool {
		svc := value.(*edge.Service)
		k := key.(string)
		if _, found := idMap[svc.Id]; !found {
			deletes = append(deletes, k)
			if context.options.OnServiceUpdate != nil {
				context.options.OnServiceUpdate(ServiceRemoved, svc)
			}
			context.deleteServiceSessions(svc.Id)
		}
		return true
	})

	for _, deletedKey := range deletes {
		context.services.Delete(deletedKey)
	}

	// Adds and Updates
	for _, s := range services {
		val, exists := context.services.LoadOrStore(s.Name, s)
		if context.options.OnServiceUpdate != nil {
			if !exists {
				context.options.OnServiceUpdate(ServiceAdded, val.(*edge.Service))
			} else {
				if !reflect.DeepEqual(val, s) {
					context.services.Store(s.Name, s) // replace
					context.options.OnServiceUpdate(ServiceChanged, s)
				}
			}
		}
	}

	serviceQueryMap := map[string]map[string]edge.PostureQuery{} //serviceId -> queryId -> query

	context.services.Range(func(serviceId, val interface{}) bool {
		if service, ok := val.(*edge.Service); ok {
			for _, querySets := range service.PostureQueries {
				for _, query := range querySets.PostureQueries {
					var queryMap map[string]edge.PostureQuery
					var ok bool
					if queryMap, ok = serviceQueryMap[service.Id]; !ok {
						queryMap = map[string]edge.PostureQuery{}
						serviceQueryMap[service.Id] = queryMap
					}
					queryMap[query.Id] = query
				}
			}
		}
		return true
	})

	context.postureCache.SetServiceQueryMap(serviceQueryMap)
}

func (context *contextImpl) refreshSessions() {
	log := pfxlog.Logger()
	edgeRouters := make(map[string]string)
	context.sessions.Range(func(key, value interface{}) bool {
		log.Debugf("refreshing session for %s", key)

		session := value.(*edge.Session)
		if s, err := context.refreshSession(session.Id); err != nil {
			log.WithError(err).Errorf("failed to refresh session for %s", key)
			context.sessions.Delete(session.Id)
		} else {
			for _, er := range s.EdgeRouters {
				for _, u := range er.Urls {
					edgeRouters[u] = er.Name
				}
			}
		}

		return true
	})

	for u, name := range edgeRouters {
		context.routerClient.RefreshEdgeRouter(name, u)
	}
}

func (context *contextImpl) runSessionRefresh() {
	log := pfxlog.Logger()
	svcUpdateTick := time.NewTicker(context.options.RefreshInterval)
	defer svcUpdateTick.Stop()

	expireTime := context.ctrlClt.GetCurrentApiSession().Expires
	sleepDuration := expireTime.Sub(time.Now()) - (10 * time.Second)

	var serviceUpdateApiAvailable = true

	for {
		select {
		case <-context.closeNotify:
			return

		case <-time.After(sleepDuration):
			exp, err := context.ctrlClt.Refresh()
			if err != nil {
				log.Errorf("could not refresh apiSession: %v", err)

				sleepDuration = 5 * time.Second
			} else {
				expireTime = *exp
				sleepDuration = expireTime.Sub(time.Now()) - (10 * time.Second)
				log.Debugf("apiSession refreshed, new expiration[%s]", expireTime)
			}

		case <-svcUpdateTick.C:
			log.Debug("refreshing services")
			checkService := false

			if serviceUpdateApiAvailable {
				var err error
				if checkService, err = context.ctrlClt.IsServiceListUpdateAvailable(); err != nil {
					log.WithError(err).Errorf("failed to check if service list update is available")
					if errors.As(err, &api.NotFound{}) {
						serviceUpdateApiAvailable = false
						checkService = true
					}
				}
			} else {
				checkService = true
			}

			if checkService {
				log.Debug("refreshing services")
				services, err := context.getServices()
				if err != nil {
					log.Errorf("failed to load service updates %+v", err)
				} else {
					context.processServiceUpdates(services)
					context.refreshSessions()
				}
			}
		}
	}
}

func (context *contextImpl) GetCurrentIdentity() (*edge.CurrentIdentity, error) {
	if err := context.initialize(); err != nil {
		return nil, errors.Wrap(err, "failed to initialize context")
	}

	if err := context.ensureApiSession(); err != nil {
		return nil, errors.Wrap(err, "failed to establish api session")
	}

	return context.ctrlClt.GetCurrentIdentity()
}

func (context *contextImpl) Authenticate() error {
	if err := context.initialize(); err != nil {
		return errors.Errorf("failed to initialize context: (%v)", err)
	}

	if context.ctrlClt.GetCurrentApiSession() != nil {
		logrus.Debug("previous apiSession detected, checking if valid")
		if _, err := context.ctrlClt.Refresh(); err == nil {
			logrus.Info("previous apiSession refreshed")
			return nil
		} else {
			logrus.WithError(err).Info("previous apiSession failed to refresh, attempting to authenticate")
		}
	}

	logrus.Debug("attempting to authenticate")
	context.services = sync.Map{}
	context.sessions = sync.Map{}

	info := sdkinfo.GetSdkInfo()
	info["appId"] = globalAppId
	info["appVersion"] = globalAppVersion

	apiSession, err := context.ctrlClt.Login(info)

	if err != nil {
		return err
	}

	if len(apiSession.AuthQueries) != 0 {
		for _, authQuery := range apiSession.AuthQueries {
			if err := context.handleAuthQuery(authQuery); err != nil {
				return err
			}
		}
	}

	context.routerClient.NotifyReauthenticated()

	var doOnceErr error
	context.firstAuthOnce.Do(func() {
		context.routerClient.OnContextReady(context)
		if context.options.OnContextReady != nil {
			context.options.OnContextReady(context)
		}
		go context.runSessionRefresh()

		metricsTags := map[string]string{
			"srcId": context.ctrlClt.GetCurrentApiSession().Identity.Id,
		}

		context.metrics = metrics.NewRegistry(context.ctrlClt.GetCurrentApiSession().Identity.Name, metricsTags)

		// get services
		if services, err := context.getServices(); err != nil {
			doOnceErr = err
		} else {
			context.processServiceUpdates(services)
		}
	})

	return doOnceErr
}

const (
	MfaProviderZiti = "ziti"
)

func (context *contextImpl) AddZitiMfaHandler(handler func(query *edge.AuthQuery, resp func(code string) error) error) {
	context.authQueryHandlers[MfaProviderZiti] = handler
}

func (context *contextImpl) handleAuthQuery(authQuery *edge.AuthQuery) error {
	if authQuery.Provider == MfaProviderZiti {
		handler := context.authQueryHandlers[MfaProviderZiti]

		if handler == nil {
			return fmt.Errorf("no handler registered for: %v", authQuery.Provider)
		}

		return handler(authQuery, context.ctrlClt.AuthenticateMFA)
	}

	return fmt.Errorf("unsupported MFA provider: %v", authQuery.Provider)
}

func (context *contextImpl) Dial(serviceName string) (edge.Conn, error) {
	defaultOptions := &DialOptions{ConnectTimeout: 5 * time.Second}
	return context.DialWithOptions(serviceName, defaultOptions)
}

func (context *contextImpl) DialWithOptions(serviceName string, options *DialOptions) (edge.Conn, error) {
	edgeDialOptions := &edge.DialOptions{
		ConnectTimeout: options.ConnectTimeout,
		Identity:       options.Identity,
		AppData:        options.AppData,
	}
	if edgeDialOptions.GetConnectTimeout() == 0 {
		edgeDialOptions.ConnectTimeout = 15 * time.Second
	}
	if err := context.initialize(); err != nil {
		return nil, errors.Errorf("failed to initialize context: (%v)", err)
	}

	if err := context.ensureApiSession(); err != nil {
		return nil, fmt.Errorf("failed to dial: %v", err)
	}

	service, ok := context.GetService(serviceName)
	if !ok {
		return nil, errors.Errorf("service '%s' not found", serviceName)
	}

	context.postureCache.AddActiveService(service.Id)

	edgeDialOptions.CallerId = context.ctrlClt.GetCurrentApiSession().Identity.Name

	var conn edge.Conn
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		var session *edge.Session
		session, err = context.GetSession(service.Id)
		if err != nil {
			context.deleteServiceSessions(service.Id)
			if _, err = context.createSessionWithBackoff(service, edge.SessionDial, options); err != nil {
				break
			}
			continue
		}
		pfxlog.Logger().Debugf("connecting via session id [%s] token [%s]", session.Id, session.Token)
		conn, err = context.routerClient.DialSession(service, session, edgeDialOptions)
		if err != nil {
			if _, refreshErr := context.refreshSession(session.Id); refreshErr != nil {
				context.deleteServiceSessions(service.Id)
				if _, err = context.createSessionWithBackoff(service, edge.SessionDial, options); err != nil {
					break
				}
			}
			continue
		}
		return conn, err
	}
	return nil, errors.Wrapf(err, "unable to dial service '%s'", serviceName)
}

func (context *contextImpl) ensureApiSession() error {
	if context.ctrlClt.GetCurrentApiSession() == nil {
		if err := context.Authenticate(); err != nil {
			return fmt.Errorf("no apiSession, authentication attempt failed: %v", err)
		}
	}
	return nil
}

func (context *contextImpl) Listen(serviceName string) (edge.Listener, error) {
	return context.ListenWithOptions(serviceName, DefaultListenOptions())
}

func (context *contextImpl) ListenWithOptions(serviceName string, options *ListenOptions) (edge.Listener, error) {
	if err := context.initialize(); err != nil {
		return nil, errors.Errorf("failed to initialize context: (%v)", err)
	}

	if err := context.ensureApiSession(); err != nil {
		return nil, fmt.Errorf("failed to listen: %v", err)
	}

	if s, ok := context.GetService(serviceName); ok {
		return context.routerClient.ListenWithOptions(s, options)
	}
	return nil, errors.Errorf("service '%s' not found", serviceName)
}

func (context *contextImpl) GetServiceId(name string) (string, bool, error) {
	if err := context.initialize(); err != nil {
		return "", false, errors.Errorf("failed to initialize context: (%v)", err)
	}

	if err := context.ensureApiSession(); err != nil {
		return "", false, fmt.Errorf("failed to get service id: %v", err)
	}

	id, found := context.getServiceId(name)
	return id, found, nil
}

func (context *contextImpl) GetService(name string) (*edge.Service, bool) {
	if err := context.initialize(); err != nil {
		return nil, false
	}

	if err := context.ensureApiSession(); err != nil {
		pfxlog.Logger().Warnf("failed to get service: %v", err)
		return nil, false
	}

	if s, found := context.services.Load(name); !found {
		return nil, false
	} else {
		return s.(*edge.Service), true
	}
}

func (context *contextImpl) getServiceId(name string) (string, bool) {
	if s, found := context.GetService(name); found {
		return s.Id, true
	}

	return "", false
}

func (context *contextImpl) GetServices() ([]edge.Service, error) {
	if err := context.initialize(); err != nil {
		return nil, errors.Errorf("failed to initialize context: (%v)", err)
	}

	if err := context.ensureApiSession(); err != nil {
		return nil, fmt.Errorf("failed to get services: %v", err)
	}

	var res []edge.Service
	context.services.Range(func(key, value interface{}) bool {
		svc := value.(*edge.Service)
		res = append(res, *svc)
		return true
	})
	return res, nil
}

func (context *contextImpl) getServices() ([]*edge.Service, error) {
	return context.ctrlClt.GetServices()
}

func (context *contextImpl) GetSession(serviceId string) (*edge.Session, error) {
	return context.getOrCreateSession(serviceId, edge.SessionDial)
}

func (context *contextImpl) getOrCreateSession(serviceId string, sessionType edge.SessionType) (*edge.Session, error) {
	if err := context.initialize(); err != nil {
		return nil, errors.Errorf("failed to initialize context: (%v)", err)
	}
	sessionKey := fmt.Sprintf("%s:%s", serviceId, sessionType)

	cache := sessionType == edge.SessionDial

	// Can't cache Bind sessions, as we use session tokens for routing. If there are multiple binds on a single
	// session routing information will get overwritten
	if cache {
		val, ok := context.sessions.Load(sessionKey)
		if ok {
			return val.(*edge.Session), nil
		}
	}

	context.postureCache.AddActiveService(serviceId)
	session, err := context.ctrlClt.CreateSession(serviceId, sessionType)

	if err != nil {
		return nil, err
	}
	context.cacheSession("create", session)
	return session, nil
}

func (context *contextImpl) createSessionWithBackoff(service *edge.Service, sessionType edge.SessionType, options edge.ConnOptions) (*edge.Session, error) {
	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.InitialInterval = 50 * time.Millisecond
	expBackoff.MaxInterval = 10 * time.Second
	expBackoff.MaxElapsedTime = options.GetConnectTimeout()

	var session *edge.Session
	operation := func() error {
		s, err := context.createSession(service, sessionType)
		if err != nil {
			return err
		}
		session = s
		return nil
	}

	if session != nil {
		context.postureCache.AddActiveService(service.Id)
		context.cacheSession("create", session)
	}

	return session, backoff.Retry(operation, expBackoff)
}

func (context *contextImpl) createSession(service *edge.Service, sessionType edge.SessionType) (*edge.Session, error) {
	start := time.Now()
	logger := pfxlog.Logger()
	logger.Debugf("establishing %v session to service %v", sessionType, service.Name)
	session, err := context.getOrCreateSession(service.Id, sessionType)
	if err != nil {
		logger.WithError(err).Warnf("failure creating %v session to service %v", sessionType, service.Name)
		if errors2.Is(err, api.NotAuthorized) {
			if err := context.Authenticate(); err != nil {
				if errors2.As(err, &api.AuthFailure{}) {
					return nil, backoff.Permanent(err)
				}
				return nil, err
			}
		} else if errors2.As(err, &api.NotAccessible{}) {
			logger.Warnf("session create failure not recoverable, not retrying")
			return nil, backoff.Permanent(err)
		}
		return nil, err
	}
	elapsed := time.Now().Sub(start)
	logger.Debugf("successfully created %v session to service %v in %vms", sessionType, service.Name, elapsed.Milliseconds())
	return session, nil
}

func (context *contextImpl) RefreshSession(session *edge.Session) (*edge.Session, error) {
	refreshedSession, err := context.refreshSession(session.Id)
	if err != nil {
		if _, isNotFound := err.(api.NotFound); isNotFound {
			sessionKey := fmt.Sprintf("%s:%s", session.Service.Id, session.Type)
			context.sessions.Delete(sessionKey)
		}
		return nil, err
	}
	return refreshedSession, err
}

func (context *contextImpl) refreshSession(id string) (*edge.Session, error) {
	if err := context.initialize(); err != nil {
		return nil, errors.Errorf("failed to initialize context: (%v)", err)
	}

	session, err := context.ctrlClt.RefreshSession(id)
	if err != nil {
		return nil, err
	}
	context.cacheSession("refresh", session)
	return session, nil
}

func (context *contextImpl) cacheSession(op string, session *edge.Session) {
	sessionKey := fmt.Sprintf("%s:%s", session.Service.Id, session.Type)

	if session.Type == edge.SessionDial {
		if op == "create" {
			context.sessions.Store(sessionKey, session)
		} else if op == "refresh" {
			// N.B.: refreshed sessions do not contain token so update stored session object with updated edgeRouters
			val, exists := context.sessions.LoadOrStore(sessionKey, session)
			if exists {
				existingSession := val.(*edge.Session)
				existingSession.EdgeRouters = session.EdgeRouters
			}
		}
	}
}

func (context *contextImpl) deleteServiceSessions(svcId string) {
	context.sessions.Delete(fmt.Sprintf("%s:%s", svcId, edge.SessionBind))
	context.sessions.Delete(fmt.Sprintf("%s:%s", svcId, edge.SessionDial))
}

func (context *contextImpl) Close() {
	if context.closed.CompareAndSwap(false, true) {
		close(context.closeNotify)
		context.routerClient.Close()
		if context.ctrlClt != nil {
			context.ctrlClt.Shutdown()
		}
	}
}

func (context *contextImpl) Metrics() metrics.Registry {
	_ = context.initialize()
	return context.metrics
}

func (context *contextImpl) EnrollZitiMfa() (*api.MfaEnrollment, error) {
	return context.ctrlClt.EnrollMfa()
}

func (context *contextImpl) VerifyZitiMfa(code string) error {
	return context.ctrlClt.VerifyMfa(code)
}
func (context *contextImpl) RemoveZitiMfa(code string) error {
	return context.ctrlClt.RemoveMfa(code)
}
