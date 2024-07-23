/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package discovery

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/sirupsen/logrus"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/client/proto"
	usageeventsv1 "github.com/gravitational/teleport/api/gen/proto/go/usageevents/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/discoveryconfig"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/api/utils/retryutils"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/cloud"
	gcpimds "github.com/gravitational/teleport/lib/cloud/imds/gcp"
	"github.com/gravitational/teleport/lib/integrations/awsoidc"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/srv/discovery/common"
	"github.com/gravitational/teleport/lib/srv/discovery/fetchers"
	aws_sync "github.com/gravitational/teleport/lib/srv/discovery/fetchers/aws-sync"
	"github.com/gravitational/teleport/lib/srv/discovery/fetchers/db"
	"github.com/gravitational/teleport/lib/srv/server"
	"github.com/gravitational/teleport/lib/utils/spreadwork"
)

var errNoInstances = errors.New("all fetched nodes already enrolled")

// Matchers contains all matchers used by discovery service
type Matchers struct {
	// AccessGraph is the configuration for the Access Graph Cloud sync.
	AccessGraph *types.AccessGraphSync
}

func (m Matchers) IsEmpty() bool {
	return (m.AccessGraph == nil || len(m.AccessGraph.AWS) == 0)
}

// Config provides configuration for the discovery server.
type Config struct {
	// CloudClients is an interface for retrieving cloud clients.
	CloudClients cloud.Clients
	// IntegrationOnlyCredentials discards any Matcher that don't have an Integration.
	// When true, ambient credentials (used by the Cloud SDKs) are not used.
	IntegrationOnlyCredentials bool
	// Matchers stores all types of matchers to discover resources
	Matchers Matchers
	// Emitter is events emitter, used to submit discrete events
	Emitter apievents.Emitter
	// AccessPoint is a discovery access point
	AccessPoint authclient.DiscoveryAccessPoint
	// Log is the logger.
	Log logrus.FieldLogger
	// ServerID identifies the Teleport instance where this service runs.
	ServerID string
	// onDatabaseReconcile is called after each database resource reconciliation.
	onDatabaseReconcile func()
	// protocolChecker is used by Kubernetes fetchers to check port's protocol if needed.
	protocolChecker fetchers.ProtocolChecker
	// DiscoveryGroup is the name of the discovery group that the current
	// discovery service is a part of.
	// It is used to filter out discovered resources that belong to another
	// discovery services. When running in high availability mode and the agents
	// have access to the same cloud resources, this field value must be the same
	// for all discovery services. If different agents are used to discover different
	// sets of cloud resources, this field must be different for each set of agents.
	DiscoveryGroup string
	// ClusterName is the name of the Teleport cluster.
	ClusterName string
	// PollInterval is the cadence at which the discovery server will run each of its
	// discovery cycles.
	// Default: [github.com/gravitational/teleport/lib/srv/discovery/common.DefaultDiscoveryPollInterval]
	PollInterval time.Duration

	// ServerCredentials are the credentials used to identify the discovery service
	// to the Access Graph service.
	ServerCredentials *tls.Config
	// AccessGraphConfig is the configuration for the Access Graph client
	AccessGraphConfig AccessGraphConfig

	// ClusterFeatures returns flags for supported/unsupported features.
	// Used as a function because cluster features might change on Auth restarts.
	ClusterFeatures func() proto.Features

	// TriggerFetchC is a list of channels that must be notified when a off-band poll must be performed.
	// This is used to start a polling iteration when a new DiscoveryConfig change is received.
	TriggerFetchC  []chan struct{}
	triggerFetchMu sync.RWMutex

	// clock is passed to watchers to handle poll intervals.
	// Mostly used in tests.
	clock clockwork.Clock

	// jitter is a function which applies random jitter to a duration.
	// It is used to add Expiration times to Resources that don't support Heartbeats (eg EICE Nodes).
	jitter retryutils.Jitter
}

// AccessGraphConfig represents TAG server config.
type AccessGraphConfig struct {
	// Enabled indicates if Access Graph reporting is enabled.
	Enabled bool

	// Addr of the Access Graph service.
	Addr string

	// CA is the CA in PEM format used by the Access Graph service.
	CA []byte

	// Insecure is true if the connection to the Access Graph service should be insecure.
	Insecure bool
}

func (c *Config) CheckAndSetDefaults() error {
	if c.Matchers.IsEmpty() && c.DiscoveryGroup == "" {
		return trace.BadParameter("no matchers or discovery group configured for discovery")
	}
	if c.Emitter == nil {
		return trace.BadParameter("no Emitter configured for discovery")
	}
	if c.AccessPoint == nil {
		return trace.BadParameter("no AccessPoint configured for discovery")
	}

	if c.Log == nil {
		c.Log = logrus.New()
	}
	if c.protocolChecker == nil {
		c.protocolChecker = fetchers.NewProtoChecker(false)
	}

	if c.PollInterval == 0 {
		c.PollInterval = common.DefaultDiscoveryPollInterval
	}

	c.TriggerFetchC = make([]chan struct{}, 0)
	c.triggerFetchMu = sync.RWMutex{}

	if c.clock == nil {
		c.clock = clockwork.NewRealClock()
	}

	if c.ClusterFeatures == nil {
		return trace.BadParameter("cluster features are required")
	}

	c.Log = c.Log.WithField(teleport.ComponentKey, teleport.ComponentDiscovery)

	if c.DiscoveryGroup == "" {
		c.Log.Warn("discovery_service.discovery_group is not set. This field is required for the discovery service to work properly.\n" +
			"Please set discovery_service.discovery_group according to the documentation: https://goteleport.com/docs/reference/config/#discovery-service")
	}

	c.jitter = retryutils.NewSeventhJitter()

	return nil
}

// Server is a discovery server, used to discover cloud resources for
// inclusion in Teleport
type Server struct {
	*Config

	ctx context.Context
	// cancelfn is used with ctx when stopping the discovery server
	cancelfn context.CancelFunc
	// nodeWatcher is a node watcher.
	nodeWatcher *services.NodeWatcher

	// databaseFetchers holds all database fetchers.
	databaseFetchers []common.Fetcher

	// dynamicMatcherWatcher is an initialized Watcher for DiscoveryConfig resources.
	// Each new event must update the existing resources.
	dynamicMatcherWatcher types.Watcher

	// dynamicDatabaseFetchers holds the current Database Fetchers for the Dynamic Matchers (those coming from DiscoveryConfig resource).
	// The key is the DiscoveryConfig name.
	dynamicDatabaseFetchers   map[string][]common.Fetcher
	muDynamicDatabaseFetchers sync.RWMutex

	// dynamicTAGSyncFetchers holds the current TAG Fetchers for the Dynamic Matchers (those coming from DiscoveryConfig resource).
	// The key is the DiscoveryConfig name.
	dynamicTAGSyncFetchers   map[string][]aws_sync.AWSSync
	muDynamicTAGSyncFetchers sync.RWMutex
	staticTAGSyncFetchers    []aws_sync.AWSSync

	dynamicDiscoveryConfig map[string]*discoveryconfig.DiscoveryConfig

	// caRotationCh receives nodes that need to have their CAs rotated.
	caRotationCh chan []types.Server
	// reconciler periodically reconciles the labels of discovered instances
	// with the auth server.
	reconciler *labelReconciler

	mu sync.Mutex
	// usageEventCache keeps track of which instances the server has emitted
	// usage events for.
	usageEventCache map[string]struct{}
}

// New initializes a discovery Server
func New(ctx context.Context, cfg *Config) (*Server, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	localCtx, cancelfn := context.WithCancel(ctx)
	s := &Server{
		Config:                     cfg,
		ctx:                        localCtx,
		cancelfn:                   cancelfn,
		usageEventCache:            make(map[string]struct{}),
		dynamicDatabaseFetchers:    make(map[string][]common.Fetcher),
		dynamicTAGSyncFetchers:     make(map[string][]aws_sync.AWSSync),
		dynamicDiscoveryConfig:     make(map[string]*discoveryconfig.DiscoveryConfig),
	}
	s.discardUnsupportedMatchers(&s.Matchers)

	if err := s.startDynamicMatchersWatcher(s.ctx); err != nil {
		return nil, trace.Wrap(err)
	}

	databaseFetchers, err := s.databaseFetchersFromMatchers(cfg.Matchers)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	s.databaseFetchers = databaseFetchers

	if err := s.initAccessGraphWatchers(s.ctx, cfg); err != nil {
		return nil, trace.Wrap(err)
	}

	return s, nil
}

// startDynamicMatchersWatcher starts a watcher for DiscoveryConfig events.
// After initialization, it starts a goroutine that receives and handles events.
func (s *Server) startDynamicMatchersWatcher(ctx context.Context) error {
	if s.DiscoveryGroup == "" {
		return nil
	}

	watcher, err := s.AccessPoint.NewWatcher(ctx, types.Watch{
		Kinds: []types.WatchKind{{
			Kind: types.KindDiscoveryConfig,
		}},
	})
	if err != nil {
		return trace.Wrap(err)
	}

	// Wait for OpInit event so the watcher is ready.
	select {
	case event := <-watcher.Events():
		if event.Type != types.OpInit {
			return trace.BadParameter("failed to watch for DiscoveryConfig: received an unexpected event while waiting for the initial OpInit")
		}
	case <-watcher.Done():
		return trace.Wrap(watcher.Error())
	}

	s.dynamicMatcherWatcher = watcher

	if err := s.loadExistingDynamicDiscoveryConfigs(); err != nil {
		return trace.Wrap(err)
	}

	go s.startDynamicWatcherUpdater()
	return nil
}

// databaseFetchersFromMatchers converts Matchers into a set of Database Fetchers.
func (s *Server) databaseFetchersFromMatchers(matchers Matchers) ([]common.Fetcher, error) {
	var fetchers []common.Fetcher

	return fetchers, nil
}

func genInstancesLogStr[T any](instances []T, getID func(T) string) string {
	var logInstances strings.Builder
	for idx, inst := range instances {
		if idx == 10 || idx == (len(instances)-1) {
			logInstances.WriteString(getID(inst))
			break
		}
		logInstances.WriteString(getID(inst) + ", ")
	}
	if len(instances) > 10 {
		logInstances.WriteString(fmt.Sprintf("... + %d instance IDs truncated", len(instances)-10))
	}

	return fmt.Sprintf("[%s]", logInstances.String())
}

func (s *Server) getMostRecentRotationForCAs(ctx context.Context, caTypes ...types.CertAuthType) (time.Time, error) {
	var mostRecentUpdate time.Time
	for _, caType := range caTypes {
		ca, err := s.AccessPoint.GetCertAuthority(ctx, types.CertAuthID{
			Type:       caType,
			DomainName: s.ClusterName,
		}, false)
		if err != nil {
			return time.Time{}, trace.Wrap(err)
		}
		caRot := ca.GetRotation()
		if caRot.State == types.RotationStateInProgress && caRot.Started.After(mostRecentUpdate) {
			mostRecentUpdate = caRot.Started
		}

		if caRot.LastRotated.After(mostRecentUpdate) {
			mostRecentUpdate = caRot.LastRotated
		}
	}
	return mostRecentUpdate, nil
}

func (s *Server) emitUsageEvents(events map[string]*usageeventsv1.ResourceCreateEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, event := range events {
		if _, exists := s.usageEventCache[name]; exists {
			continue
		}
		s.usageEventCache[name] = struct{}{}
		if err := s.AccessPoint.SubmitUsageEvent(s.ctx, &proto.SubmitUsageEventRequest{
			Event: &usageeventsv1.UsageEventOneOf{
				Event: &usageeventsv1.UsageEventOneOf_ResourceCreateEvent{
					ResourceCreateEvent: event,
				},
			},
		}); err != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

func (s *Server) submitFetchersEvent(fetchers []common.Fetcher) {
	// Some Matcher Types have multiple fetchers, but we only care about the Matcher Type and not the actual Fetcher.
	// Example:
	// The `rds` Matcher Type creates two Fetchers: one for RDS and another one for Aurora
	// Those fetchers's `FetcherType` both return `rds`, so we end up with two entries for `rds`.
	// We must de-duplicate those entries before submitting the event.
	type fetcherType struct {
		cloud       string
		fetcherType string
	}
	fetcherTypes := map[fetcherType]struct{}{}
	for _, f := range fetchers {
		fetcherKey := fetcherType{cloud: f.Cloud(), fetcherType: f.FetcherType()}
		fetcherTypes[fetcherKey] = struct{}{}
	}
	for f := range fetcherTypes {
		s.submitFetchEvent(f.cloud, f.fetcherType)
	}
}

func (s *Server) submitFetchEvent(cloudProvider, resourceType string) {
	err := s.AccessPoint.SubmitUsageEvent(s.ctx, &proto.SubmitUsageEventRequest{
		Event: &usageeventsv1.UsageEventOneOf{
			Event: &usageeventsv1.UsageEventOneOf_DiscoveryFetchEvent{
				DiscoveryFetchEvent: &usageeventsv1.DiscoveryFetchEvent{
					CloudProvider: cloudProvider,
					ResourceType:  resourceType,
				},
			},
		},
	})
	if err != nil {
		s.Log.WithError(err).Debug("Error emitting discovery fetch event.")
	}
}

// Start starts the discovery service.
func (s *Server) Start() error {
	if err := s.startDatabaseWatchers(); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// loadExistingDynamicDiscoveryConfigs loads all the dynamic discovery configs for the current discovery group
// and setups their matchers.
func (s *Server) loadExistingDynamicDiscoveryConfigs() error {
	// Add all existing DiscoveryConfigs as matchers.
	nextKey := ""
	for {
		dcs, respNextKey, err := s.AccessPoint.ListDiscoveryConfigs(s.ctx, 0, nextKey)
		if err != nil {
			s.Log.WithError(err).Warnf("failed to list discovery configs")
			return trace.Wrap(err)
		}

		for _, dc := range dcs {
			if dc.GetDiscoveryGroup() != s.DiscoveryGroup {
				continue
			}
			if err := s.upsertDynamicMatchers(s.ctx, dc); err != nil {
				s.Log.WithError(err).Warnf("failed to update dynamic matchers for discovery config %q", dc.GetName())
				continue
			}
			s.dynamicDiscoveryConfig[dc.GetName()] = dc
		}
		if respNextKey == "" {
			break
		}
		nextKey = respNextKey
	}
	return nil
}

// startDynamicWatcherUpdater watches for DiscoveryConfig resource change events.
// Before consuming changes, it iterates over all DiscoveryConfigs and
// For deleted resources, it deletes the matchers.
// For new/updated resources, it replaces the set of fetchers.
func (s *Server) startDynamicWatcherUpdater() {
	// Consume DiscoveryConfig events to update Matchers as they change.
	for {
		select {
		case event := <-s.dynamicMatcherWatcher.Events():
			switch event.Type {
			case types.OpPut:
				dc, ok := event.Resource.(*discoveryconfig.DiscoveryConfig)
				if !ok {
					s.Log.Warnf("dynamic matcher watcher: unexpected resource type %T", event.Resource)
					return
				}

				if dc.GetDiscoveryGroup() != s.DiscoveryGroup {
					name := dc.GetName()
					// If the DiscoveryConfig was never part part of this discovery service because the
					// discovery group never matched, then it must be ignored.
					if _, ok := s.dynamicDiscoveryConfig[name]; !ok {
						continue
					}
					// Let's assume there's a DiscoveryConfig DC1 has DiscoveryGroup DG1, which this process is monitoring.
					// If the user updates the DiscoveryGroup to DG2, then DC1 must be removed from the scope of this process.
					// We blindly delete it, in the worst case, this is a no-op.
					s.deleteDynamicFetchers(name)
					delete(s.dynamicDiscoveryConfig, name)
					s.notifyDiscoveryConfigChanged()
					continue
				}

				oldDiscoveryConfig := s.dynamicDiscoveryConfig[dc.GetName()]
				// If the DiscoveryConfig spec didn't change, then there's no need to update the matchers.
				// we can skip this event.
				if oldDiscoveryConfig.IsEqual(dc) {
					continue
				}

				if err := s.upsertDynamicMatchers(s.ctx, dc); err != nil {
					s.Log.WithError(err).Warnf("failed to update dynamic matchers for discovery config %q", dc.GetName())
					continue
				}
				s.dynamicDiscoveryConfig[dc.GetName()] = dc
				s.notifyDiscoveryConfigChanged()

			case types.OpDelete:
				name := event.Resource.GetName()
				// If the DiscoveryConfig was never part part of this discovery service because the
				// discovery group never matched, then it must be ignored.
				if _, ok := s.dynamicDiscoveryConfig[name]; !ok {
					continue
				}
				s.deleteDynamicFetchers(name)
				delete(s.dynamicDiscoveryConfig, name)
				s.notifyDiscoveryConfigChanged()
			default:
				s.Log.Warnf("Skipping unknown event type %s", event.Type)
			}
		case <-s.dynamicMatcherWatcher.Done():
			s.Log.Warnf("dynamic matcher watcher error: %v", s.dynamicMatcherWatcher.Error())
			return
		}
	}
}

// newDiscoveryConfigChangedSub creates a new subscription for DiscoveryConfig events.
// The consumer must have an active reader on the returned channel, and start a new Poll when it returns a value.
func (s *Server) newDiscoveryConfigChangedSub() (ch chan struct{}) {
	chSubscription := make(chan struct{}, 1)
	s.triggerFetchMu.Lock()
	s.TriggerFetchC = append(s.TriggerFetchC, chSubscription)
	s.triggerFetchMu.Unlock()
	return chSubscription
}

// triggerPoll sends a notification to all the registered watchers so that they start a new Poll.
func (s *Server) notifyDiscoveryConfigChanged() {
	s.triggerFetchMu.RLock()
	defer s.triggerFetchMu.RUnlock()
	for _, watcherTriggerC := range s.TriggerFetchC {
		select {
		case watcherTriggerC <- struct{}{}:
			// Successfully sent notification.
		default:
			// Channel already has valued queued.
		}
	}
}

func (s *Server) deleteDynamicFetchers(name string) {
	s.muDynamicDatabaseFetchers.Lock()
	delete(s.dynamicDatabaseFetchers, name)
	s.muDynamicDatabaseFetchers.Unlock()
}

// upsertDynamicMatchers upserts the internal set of dynamic matchers given a particular discovery config.
func (s *Server) upsertDynamicMatchers(ctx context.Context, dc *discoveryconfig.DiscoveryConfig) error {
	matchers := Matchers{
		AccessGraph: dc.Spec.AccessGraph,
	}
	s.discardUnsupportedMatchers(&matchers)

	databaseFetchers, err := s.databaseFetchersFromMatchers(matchers)
	if err != nil {
		return trace.Wrap(err)
	}

	awsSyncMatchers, err := s.accessGraphFetchersFromMatchers(
		ctx, matchers, dc.GetName(),
	)
	if err != nil {
		return trace.Wrap(err)
	}
	s.muDynamicTAGSyncFetchers.Lock()
	s.dynamicTAGSyncFetchers[dc.GetName()] = awsSyncMatchers
	s.muDynamicTAGSyncFetchers.Unlock()

	return nil
}

// discardUnsupportedMatchers drops any matcher that is not supported in the current DiscoveryService.
// Discarded Matchers:
// - when running in IntegrationOnlyCredentials mode, any Matcher that doesn't have an Integration is discarded.
func (s *Server) discardUnsupportedMatchers(m *Matchers) {
	if !s.IntegrationOnlyCredentials {
		return
	}
}

// Stop stops the discovery service.
func (s *Server) Stop() {
	s.cancelfn()
	if s.dynamicMatcherWatcher != nil {
		if err := s.dynamicMatcherWatcher.Close(); err != nil {
			s.Log.Warnf("dynamic matcher watcher closing error: ", trace.Wrap(err))
		}
	}
}

// Wait will block while the server is running.
func (s *Server) Wait() error {
	<-s.ctx.Done()
	if err := s.ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
		return trace.Wrap(err)
	}
	return nil
}


func (s *Server) initTeleportNodeWatcher() (err error) {
	s.nodeWatcher, err = services.NewNodeWatcher(s.ctx, services.NodeWatcherConfig{
		ResourceWatcherConfig: services.ResourceWatcherConfig{
			Component:    teleport.ComponentDiscovery,
			Log:          s.Log,
			Client:       s.AccessPoint,
			MaxStaleness: time.Minute,
		},
	})

	return trace.Wrap(err)
}

// splitSlice splits a slice into two, by putting all elements that satisfy the
// provided check function in the first slice, while putting all other elements
// in the second slice.
func splitSlice(ss []string, check func(string) bool) (split, other []string) {
	for _, e := range ss {
		if check(e) {
			split = append(split, e)
		} else {
			other = append(other, e)
		}
	}
	return
}

// splitMatchers splits a set of matchers by checking the matcher type.
func splitMatchers[T types.Matcher](matchers []T, matcherTypeCheck func(string) bool) (split, other []T) {
	for _, matcher := range matchers {
		splitTypes, otherTypes := splitSlice(matcher.GetTypes(), matcherTypeCheck)

		if len(splitTypes) > 0 {
			newMatcher := matcher.CopyWithTypes(splitTypes).(T)
			split = append(split, newMatcher)
		}
		if len(otherTypes) > 0 {
			newMatcher := matcher.CopyWithTypes(otherTypes).(T)
			other = append(other, newMatcher)
		}
	}
	return
}

func (s *Server) updatesEmptyDiscoveryGroup(getter func() (types.ResourceWithLabels, error)) bool {
	if s.DiscoveryGroup == "" {
		return false
	}
	old, err := getter()
	if err != nil {
		return false
	}
	oldDiscoveryGroup, _ := old.GetLabel(types.TeleportInternalDiscoveryGroupName)
	return oldDiscoveryGroup == ""
}
