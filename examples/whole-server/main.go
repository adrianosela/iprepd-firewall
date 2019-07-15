package main

import (
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/adrianosela/iprepd-firewall/fwmw"
	"github.com/gorilla/mux"
)

func yourHandler() http.Handler {
	r := mux.NewRouter()

	r.Methods("GET").Path("/").HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("your IP is authorized!"))
			return
		},
	)

	return r

}

func main() {
	fw := fwmw.Firewall{
		// [required] url of the iprepd instance to use
		IPrepdURL: os.Getenv("IPREPD_HOST_URL"),
		// [required] auth string to authenticate against iprepd
		IPrepdAuthStr: os.Getenv("IPREPD_AUTH_STR"),
		// [required] reject any ip with reputation below a given score
		RejectBelowScore: 100,
		// optionally add IPs you wish to unconditionally allow
		Whitelist: []net.IP{},
		// optionally log all dropped http requests
		LogBlocked: true,
		// optionally allow any request if there was a problem reaching iprepd
		FailOpen: false,
		// optionally use non-default http client settings
		HTTPClient: &http.Client{Timeout: time.Second * 10},
	}

	err := http.ListenAndServe(":3333", fw.Wrap(yourHandler()))
	if err != nil {
		log.Fatal("ListenAndServe Error: ", err)
	}
}
