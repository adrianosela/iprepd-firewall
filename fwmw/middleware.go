package fwmw

import (
	"errors"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/adrianosela/iprepd"
)

// Firewall is a software defined firewall for HTTP servers
type Firewall struct {
	IPrepdURL        string
	IPrepdAuthStr    string
	RejectBelowScore int
	Whitelist        []net.IP
	LogBlocked       bool
	FailOpen         bool
	HTTPClient       *http.Client
}

const fwLogPrefix = "[iprepd-firewall]"

var errNoEntry = errors.New("non 200 status code received: 404")

// Wrap the firewall around an HTTP handler
func (fw *Firewall) Wrap(h http.Handler) http.Handler {
	if fw.IPrepdURL == "" {
		log.Fatalf("%s argument \"IPrepdAuthURL\" cannot be empty", fwLogPrefix)
	}
	if fw.IPrepdAuthStr == "" {
		log.Fatalf("%s argument \"IPrepdAuthStr\" cannot be empty", fwLogPrefix)
	}
	if fw.RejectBelowScore <= 0 {
		log.Fatalf("%s argument \"RejectBelowScore\" must be greater than 0", fwLogPrefix)
	}
	c, err := iprepd.NewClient(fw.IPrepdURL, fw.IPrepdAuthStr, fw.HTTPClient)
	if err != nil {
		log.Fatalf("%s could not initialize iprepd client: %s", fwLogPrefix, err)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// extract IP from http.Request
		srcIP := net.ParseIP(strings.Split(r.RemoteAddr, ":")[0])
		// check whitelist
		if !isWhitelisted(srcIP, fw.Whitelist) {
			rep, err := c.GetReputation("ip", srcIP.String())
			if err != nil {
				if err == errNoEntry {
					// not finding a reputation entry implies the
					// ip does not have any violations applied to it
					// so we let is pass...
				} else {
					// if there was an error with iprepd we only let
					// the http request through if the user explicitly
					// set the FailOpen option to true
					if !fw.FailOpen {
						if fw.LogBlocked {
							log.Printf(
								"%s an error occured getting ip reputation, blocking %s, error: %s",
								fwLogPrefix,
								srcIP.String(),
								err,
							)
						}
						w.WriteHeader(http.StatusForbidden)
						return
					}
				}
			}
			if rep.Reputation < fw.RejectBelowScore {
				if fw.LogBlocked {
					log.Printf(
						"%s blocking %s due to reputation %d less than min %d",
						fwLogPrefix,
						srcIP.String(),
						rep.Reputation,
						fw.RejectBelowScore,
					)
				}
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

// isWhitelisted checks whether an IP address is part of a list of trusted IPs
func isWhitelisted(src net.IP, trusted []net.IP) bool {
	if src == nil || trusted == nil {
		return false
	}
	for _, ip := range trusted {
		if src.Equal(ip) {
			return true
		}
	}
	return false
}
