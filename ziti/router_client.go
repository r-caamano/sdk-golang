package ziti

import (
	"fmt"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/foundation/channel2"
	"github.com/openziti/foundation/common"
	"github.com/openziti/foundation/identity/identity"
	"github.com/openziti/foundation/metrics"
	"github.com/openziti/foundation/transport"
	"github.com/openziti/sdk-golang/ziti/edge"
	"github.com/openziti/sdk-golang/ziti/edge/impl"
	cmap "github.com/orcaman/concurrent-map"
	"github.com/pkg/errors"
	metrics2 "github.com/rcrowley/go-metrics"
	"github.com/sirupsen/logrus"
	"math"
	"time"
)

type RouterClient interface {
	OnContextReady(context Context)
	NotifyReauthenticated()
	DialSession(service *edge.Service, session *edge.Session, options *edge.DialOptions) (edge.Conn, error)
	ListenWithOptions(service *edge.Service, options *ListenOptions) (edge.Listener, error)
	RefreshEdgeRouter(name, url string)
	Close()
}

func NewNetworkRouterClient() RouterClient {
	return &NetworkRouterClient{
		routerConnections: cmap.New(),
	}
}

type NetworkRouterClient struct {
	context           *contextImpl
	routerConnections cmap.ConcurrentMap
}

func (self *NetworkRouterClient) OnContextReady(context Context) {
	self.context = context.(*contextImpl)
}

func (self *NetworkRouterClient) Close() {
	for entry := range self.routerConnections.IterBuffered() {
		key, val := entry.Key, entry.Val.(edge.RouterConn)
		if !val.IsClosed() {
			if err := val.Close(); err != nil {
				pfxlog.Logger().WithError(err).Error("error while closing connection")
			}
		}
		self.routerConnections.Remove(key)
	}
}

func (self *NetworkRouterClient) RefreshEdgeRouter(name, url string) {
	go self.connectEdgeRouter(name, url, nil)
}

func (self *NetworkRouterClient) DialSession(service *edge.Service, session *edge.Session, options *edge.DialOptions) (edge.Conn, error) {
	edgeConnFactory, err := self.getEdgeRouterConn(session, options)
	if err != nil {
		return nil, err
	}
	return edgeConnFactory.Connect(service, session, options)
}

func (self *NetworkRouterClient) getEdgeRouterConn(session *edge.Session, options edge.ConnOptions) (edge.RouterConn, error) {
	logger := pfxlog.Logger().WithField("ns", session.Token)

	if len(session.EdgeRouters) == 0 {
		if refreshedSession, err := self.context.RefreshSession(session); err != nil {
			return nil, fmt.Errorf("no edge routers available, refresh errored: %v", err)
		} else {
			if len(refreshedSession.EdgeRouters) == 0 {
				return nil, errors.New("no edge routers available, refresh yielded no new edge routers")
			}
			session = refreshedSession
		}
	}

	// go through connected routers first
	bestLatency := time.Duration(math.MaxInt64)
	var bestER edge.RouterConn
	var unconnected []edge.EdgeRouter
	for _, edgeRouter := range session.EdgeRouters {
		for _, routerUrl := range edgeRouter.Urls {
			if er, found := self.routerConnections.Get(routerUrl); found {
				h := self.context.Metrics().Histogram("latency." + routerUrl).(metrics2.Histogram)
				if h.Mean() < float64(bestLatency) {
					bestLatency = time.Duration(int64(h.Mean()))
					bestER = er.(edge.RouterConn)
				}
			} else {
				unconnected = append(unconnected, edgeRouter)
			}
		}
	}

	var ch chan *edgeRouterConnResult
	if bestER == nil {
		ch = make(chan *edgeRouterConnResult, len(unconnected))
	}

	for _, edgeRouter := range unconnected {
		for _, routerUrl := range edgeRouter.Urls {
			go self.connectEdgeRouter(edgeRouter.Name, routerUrl, ch)
		}
	}

	if bestER != nil {
		logger.Debugf("selected router[%s@%s] for best latency(%d ms)",
			bestER.GetRouterName(), bestER.Key(), bestLatency.Milliseconds())
		return bestER, nil
	}

	timeout := time.After(options.GetConnectTimeout())
	for {
		select {
		case f := <-ch:
			if f.routerConnection != nil {
				logger.Debugf("using edgeRouter[%s]", f.routerConnection.Key())
				return f.routerConnection, nil
			}
		case <-timeout:
			return nil, errors.New("no edge routers connected in time")
		}
	}
}

func (self *NetworkRouterClient) connectEdgeRouter(routerName, ingressUrl string, ret chan *edgeRouterConnResult) {
	logger := pfxlog.Logger()

	retF := func(res *edgeRouterConnResult) {
		select {
		case ret <- res:
		default:
		}
	}

	if edgeConn, found := self.routerConnections.Get(ingressUrl); found {
		conn := edgeConn.(edge.RouterConn)
		if !conn.IsClosed() {
			retF(&edgeRouterConnResult{routerUrl: ingressUrl, routerConnection: conn})
			return
		} else {
			self.routerConnections.Remove(ingressUrl)
		}
	}

	ingAddr, err := transport.ParseAddress(ingressUrl)
	if err != nil {
		logger.WithError(err).Errorf("failed to parse url[%s]", ingressUrl)
		retF(&edgeRouterConnResult{routerUrl: ingressUrl, err: err})
		return
	}

	apiSession := self.context.GetCurrentApiSession()
	pfxlog.Logger().Infof("connection to edge router using token %v", apiSession.Token)
	dialer := channel2.NewClassicDialer(identity.NewIdentity(self.context.GetClientIdentity()), ingAddr, map[int32][]byte{
		edge.SessionTokenHeader: []byte(apiSession.Token),
	})

	start := time.Now().UnixNano()
	ch, err := channel2.NewChannel("ziti-sdk", dialer, nil)
	if err != nil {
		logger.Error(err)
		retF(&edgeRouterConnResult{routerUrl: ingressUrl, err: err})
		return
	}
	connectTime := time.Duration(time.Now().UnixNano() - start)
	logger.Debugf("routerConn[%s@%s] connected in %d ms", routerName, ingressUrl, connectTime.Milliseconds())

	if versionHeader, found := ch.Underlay().Headers()[channel2.HelloVersionHeader]; found {
		versionInfo, err := common.StdVersionEncDec.Decode(versionHeader)
		if err != nil {
			pfxlog.Logger().Errorf("could not parse hello version header: %v", err)
		} else {
			pfxlog.Logger().
				WithField("os", versionInfo.OS).
				WithField("arch", versionInfo.Arch).
				WithField("version", versionInfo.Version).
				WithField("revision", versionInfo.Revision).
				WithField("buildDate", versionInfo.BuildDate).
				Debug("connected to edge router")
		}
	}

	edgeConn := impl.NewEdgeConnFactory(routerName, ingressUrl, ch, self)
	logger.Debugf("connected to %s", ingressUrl)

	useConn := self.routerConnections.Upsert(ingressUrl, edgeConn,
		func(exist bool, oldV interface{}, newV interface{}) interface{} {
			if exist { // use the routerConnection already in the map, close new one
				go func() {
					if err := newV.(edge.RouterConn).Close(); err != nil {
						pfxlog.Logger().Errorf("unable to close router connection (%v)", err)
					}
				}()
				return oldV
			}
			h := self.context.Metrics().Histogram("latency." + ingressUrl)
			h.Update(int64(connectTime))
			go metrics.ProbeLatency(ch, h, LatencyCheckInterval)
			return newV
		})

	retF(&edgeRouterConnResult{routerUrl: ingressUrl, routerConnection: useConn.(edge.RouterConn)})
}

func (self *NetworkRouterClient) NotifyReauthenticated() {
	// router connections are establishing using the api token. If we re-authenticate we must re-establish connections
	self.routerConnections.IterCb(func(key string, v interface{}) {
		_ = v.(edge.RouterConn).Close()
	})

	self.routerConnections = cmap.New()
}

func (self *NetworkRouterClient) OnClose(factory edge.RouterConn) {
	logrus.Debugf("connection to router [%s] was closed", factory.Key())
	self.routerConnections.Remove(factory.Key())
}

func (self *NetworkRouterClient) ListenWithOptions(service *edge.Service, options *ListenOptions) (edge.Listener, error) {
	edgeListenOptions := &edge.ListenOptions{
		Cost:                  options.Cost,
		Precedence:            edge.Precedence(options.Precedence),
		ConnectTimeout:        options.ConnectTimeout,
		MaxConnections:        options.MaxConnections,
		Identity:              options.Identity,
		BindUsingEdgeIdentity: options.BindUsingEdgeIdentity,
		ManualStart:           options.ManualStart,
	}

	if edgeListenOptions.ConnectTimeout == 0 {
		edgeListenOptions.ConnectTimeout = time.Minute
	}

	if edgeListenOptions.MaxConnections < 1 {
		edgeListenOptions.MaxConnections = 1
	}

	listenerMgr := newListenerManager(service, self.context, self, edgeListenOptions)
	return listenerMgr.listener, nil
}
