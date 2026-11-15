package hscontrol

import (
	"github.com/juanfont/headscale/hscontrol/graph"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"tailscale.com/envknob"
)

var debugHighCardinalityMetrics = envknob.Bool("HEADSCALE_DEBUG_HIGH_CARDINALITY_METRICS")

var mapResponseLastSentSeconds *prometheus.GaugeVec

func init() {
	if debugHighCardinalityMetrics {
		mapResponseLastSentSeconds = promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: prometheusNamespace,
			Name:      "mapresponse_last_sent_seconds",
			Help:      "last sent metric to node.id",
		}, []string{"type", "id"})
	}
}

const prometheusNamespace = "headscale"

var (
	mapResponseSent = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "mapresponse_sent_total",
		Help:      "total count of mapresponses sent to clients",
	}, []string{"status", "type"})
	mapResponseEndpointUpdates = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "mapresponse_endpoint_updates_total",
		Help:      "total count of endpoint updates received",
	}, []string{"status"})
	mapResponseEnded = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "mapresponse_ended_total",
		Help:      "total count of new mapsessions ended",
	}, []string{"reason"})
	_ = promauto.NewCounterFunc(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "graph_map_log_misses_total",
		Help:      "Map diffs whose reader was beyond the edit log and compared every key.",
	}, func() float64 { return float64(graph.MapLogMisses()) })
)
