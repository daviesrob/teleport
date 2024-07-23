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

package clusters

import (
	"context"
	"crypto/tls"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/mfa"
	"github.com/gravitational/teleport/lib/client"
	libmfa "github.com/gravitational/teleport/lib/client/mfa"
	"github.com/gravitational/teleport/lib/teleterm/api/uri"
	"github.com/gravitational/teleport/lib/teleterm/gateway"
)

type CreateGatewayParams struct {
	// TargetURI is the cluster resource URI
	TargetURI uri.ResourceURI
	// TargetUser is the target user name
	TargetUser string
	// TargetSubresourceName points at a subresource of the remote resource, for example a database
	// name on a database server.
	TargetSubresourceName string
	// LocalPort is the gateway local port
	LocalPort            string
	TCPPortAllocator     gateway.TCPPortAllocator
	OnExpiredCert        gateway.OnExpiredCertFunc
	KubeconfigsDir       string
	MFAPromptConstructor func(cfg *libmfa.PromptConfig) mfa.Prompt
	ClusterClient        *client.ClusterClient
}

// CreateGateway creates a gateway
func (c *Cluster) CreateGateway(ctx context.Context, params CreateGatewayParams) (gateway.Gateway, error) {
	c.clusterClient.MFAPromptConstructor = params.MFAPromptConstructor

	switch {
	case params.TargetURI.IsApp():
		gateway, err := c.createAppGateway(ctx, params)
		return gateway, trace.Wrap(err)

	default:
		return nil, trace.NotImplemented("gateway not supported for %v", params.TargetURI)
	}
}

func (c *Cluster) createAppGateway(ctx context.Context, params CreateGatewayParams) (gateway.Gateway, error) {
	appName := params.TargetURI.GetAppName()

	app, err := c.getApp(ctx, params.ClusterClient.AuthClient, appName)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var cert tls.Certificate

	if err := AddMetadataToRetryableError(ctx, func() error {
		cert, err = c.ReissueAppCert(ctx, params.ClusterClient, app)
		return trace.Wrap(err)
	}); err != nil {
		return nil, trace.Wrap(err)
	}

	gw, err := gateway.New(gateway.Config{
		LocalPort:                     params.LocalPort,
		TargetURI:                     params.TargetURI,
		TargetName:                    appName,
		Cert:                          cert,
		Protocol:                      app.GetProtocol(),
		Insecure:                      c.clusterClient.InsecureSkipVerify,
		WebProxyAddr:                  c.clusterClient.WebProxyAddr,
		Log:                           c.Log,
		TCPPortAllocator:              params.TCPPortAllocator,
		OnExpiredCert:                 params.OnExpiredCert,
		Clock:                         c.clock,
		TLSRoutingConnUpgradeRequired: c.clusterClient.TLSRoutingConnUpgradeRequired,
		RootClusterCACertPoolFunc:     c.clusterClient.RootClusterCACertPool,
		ClusterName:                   c.Name,
		Username:                      c.status.Username,
	})
	return gw, trace.Wrap(err)
}

// ReissueGatewayCerts reissues certificate for the provided gateway.
func (c *Cluster) ReissueGatewayCerts(ctx context.Context, clusterClient *client.ClusterClient, g gateway.Gateway) (tls.Certificate, error) {
	switch {
	case g.TargetURI().IsApp():
		appName := g.TargetURI().GetAppName()
		app, err := c.getApp(ctx, clusterClient.AuthClient, appName)
		if err != nil {
			return tls.Certificate{}, trace.Wrap(err)
		}

		// The cert is returned from this function and finally set on LocalProxy by the middleware.
		cert, err := c.ReissueAppCert(ctx, clusterClient, app)
		return cert, trace.Wrap(err)
	default:
		return tls.Certificate{}, trace.NotImplemented("ReissueGatewayCerts does not support this gateway kind %v", g.TargetURI().String())
	}
}
