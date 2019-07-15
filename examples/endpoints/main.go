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

var (
	getRootHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("your IP is authorized for the GET / endpoint!"))
		return
	}
	headRootHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("your IP is authorized for the HEAD / endpoint!"))
		return
	}
	postRootHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("your IP is authorized for the POST / endpoint!"))
		return
	}
	deleteRootHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("your IP is authorized for the DELETE / endpoint!"))
		return
	}
)

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

	rtr := mux.NewRouter()
	// some endpoints can be wrapped
	rtr.Methods(http.MethodPost).Path("/").Handler(fw.Wrap(http.HandlerFunc(postRootHandler)))
	rtr.Methods(http.MethodDelete).Path("/").Handler(fw.Wrap(http.HandlerFunc(deleteRootHandler)))
	// not all of them have to be
	rtr.Methods(http.MethodGet).Path("/").Handler(http.HandlerFunc(getRootHandler))
	rtr.Methods(http.MethodHead).Path("/").Handler(http.HandlerFunc(headRootHandler))

	err := http.ListenAndServe(":8080", rtr)
	if err != nil {
		log.Fatal("ListenAndServe Error: ", err)
	}
}
