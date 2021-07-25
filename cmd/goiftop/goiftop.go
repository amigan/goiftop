package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/amigan/goiftop/internal/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/gorilla/websocket"
	"math"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"syscall"
	"time"
)

var AppVersion = "0.0.1"

type Config struct {
	ifaceName string
	filter string
	enableLayer4 bool
	port int
}

func main() {
	showVersion := false
	cfg := Config{}

	flag.StringVar(&cfg.ifaceName, "i", "", "Interface name")
	flag.StringVar(&cfg.filter, "bpf", "", "BPF filter")
	flag.BoolVar(&cfg.enableLayer4, "l4", false, "Show transport layer flows")
	flag.IntVar(&cfg.port, "p", 16384, "Http server listening port")
	flag.BoolVar(&showVersion, "v", false, "Version")
	flag.Parse()

	if showVersion {
		fmt.Println(AppVersion)
		os.Exit(0)
	}

	go func() {
		log.Infof("Start HTTP Server on port %d\n", cfg.port)
		http.HandleFunc("/l3flow", L3FlowHandler)
		http.HandleFunc("/l4flow", L4FlowHandler)
		http.HandleFunc("/ws", WsHandler)
		http.Handle("/", http.StripPrefix("/", http.FileServer(AssetFile())))

		err := http.ListenAndServe(":"+strconv.Itoa(cfg.port), nil)
		if err != nil {
			log.Errorf("Failed to start http server with error: %s\n" + err.Error())
			os.Exit(0)
		}
	}()

	if os.Geteuid() != 0 {
		log.Errorln("Must run as root")
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGHUP, syscall.SIGINT)
	tickStatsDuration := time.Tick(time.Duration(1) * time.Second)

	Stats.ifaces[cfg.ifaceName] = NewIface(cfg.ifaceName)
	ctx, cancel := context.WithCancel(context.Background())
	go listenPacket(cfg, ctx)

	for {
		select {
		case <-tickStatsDuration:
			fmt.Println("------")
			updateL3FlowSnapshots(cfg.ifaceName)
			printFlowSnapshots(L3FlowSnapshots)
			if cfg.enableLayer4 {
				fmt.Println()
				updateL4FlowSnapshots(cfg.ifaceName)
				printFlowSnapshots(L4FlowSnapshots)
			}
		case <-signalChan:
			cancel()
			goto END
		}
	}

END:
	log.Infoln("Exit...")
}

func listenPacket(cfg Config, ctx context.Context) {
	handle, err := pcap.OpenLive(cfg.ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Errorf("Failed to OpenLive by pcap, err: %s\n", err.Error())
		os.Exit(0)
	}

	err = handle.SetBPFFilter(cfg.filter)
	if err != nil {
		log.Errorf("Failed to set BPF filter, err: %s\n", err.Error())
		os.Exit(0)
	}

	defer handle.Close()

	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-ps.Packets():
			go Stats.PacketHandler(cfg, p)
		}
	}
}

func updateL3FlowSnapshots(ifaceName string) {
	L3FlowSnapshots = make([]*FlowSnapshot, 0, 0)
	Stats.ifaces[ifaceName].UpdateL3FlowQueue()
	for _, v := range Stats.ifaces[ifaceName].L3Flows {
		fss := v.GetSnapshot()
		if fss.DownStreamRate1+fss.UpStreamRate1+fss.DownStreamRate15+fss.UpStreamRate15+fss.DownStreamRate60+fss.UpStreamRate60 > 0 {
			L3FlowSnapshots = append(L3FlowSnapshots, fss)
		}
	}

	sort.Slice(L3FlowSnapshots, func(i, j int) bool {
		return math.Max(float64(L3FlowSnapshots[i].UpStreamRate1), float64(L3FlowSnapshots[i].DownStreamRate1)) >
			math.Max(float64(L3FlowSnapshots[j].UpStreamRate1), float64(L3FlowSnapshots[j].DownStreamRate1))
	})
}

func updateL4FlowSnapshots(ifaceName string) {
	L4FlowSnapshots = make([]*FlowSnapshot, 0, 0)
	Stats.ifaces[ifaceName].UpdateL4FlowQueue()
	for _, v := range Stats.ifaces[ifaceName].L4Flows {
		fss := v.GetSnapshot()
		if fss.DownStreamRate1+fss.UpStreamRate1+fss.DownStreamRate15+fss.UpStreamRate15+fss.DownStreamRate60+fss.UpStreamRate60 > 0 {
			L4FlowSnapshots = append(L4FlowSnapshots, fss)
		}
	}

	sort.Slice(L4FlowSnapshots, func(i, j int) bool {
		return math.Max(float64(L4FlowSnapshots[i].UpStreamRate1), float64(L4FlowSnapshots[i].DownStreamRate1)) >
			math.Max(float64(L4FlowSnapshots[j].UpStreamRate1), float64(L4FlowSnapshots[j].DownStreamRate1))
	})
}

func printFlowSnapshots(flowSnapshots []*FlowSnapshot) {
	if len(flowSnapshots) > 0 {
		fmt.Printf("%-8s %-32s %-32s %-16s %-16s %-16s %-16s %-16s %-16s\n", "Protocol", "Src", "Dst", "Up1", "Down1", "Up15", "Down15", "Up60", "Down60")
	}

	for _, f := range flowSnapshots {
		u1 := rateToStr(f.UpStreamRate1)
		d1 := rateToStr(f.DownStreamRate1)
		u15 := rateToStr(f.UpStreamRate15)
		d15 := rateToStr(f.DownStreamRate15)
		u60 := rateToStr(f.UpStreamRate60)
		d60 := rateToStr(f.DownStreamRate60)
		fmt.Printf("%-8s %-32s %-32s %-16s %-16s %-16s %-16s %-16s %-16s\n", f.Protocol, f.SourceAddress, f.DestinationAddress, u1, d1, u15, d15, u60, d60)
	}
}

func rateToStr(rate int64) (rs string) {
	if rate >= 1000000 {
		rs = fmt.Sprintf("%.2f Mbps", float64(rate)/float64(1000000))
	} else if rate >= 1000 && rate < 1000000 {
		rs = fmt.Sprintf("%.2f Kbps", float64(rate)/float64(1000))
	} else {
		rs = fmt.Sprintf("%d bps", rate)
	}

	return
}
