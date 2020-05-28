package fwmw

import (
	"errors"
	"log"
	"net"
	"net/http"
	"strings"

	"go.mozilla.org/iprepd"
)

// Firewall is a software defined firewall for HTTP servers. It uses Reputation
// entries from a trusted iprepd instance and built-in configuration parameters
// in order to determine whether an HTTP request should be served or not given
// the request's source ip address
type Firewall struct {
	// [required] url of the iprepd instance to use
	IPrepdURL string

	// [required] auth string to authenticate against iprepd
	IPrepdAuthStr string

	// [required] reject any ip with reputation below this score
	RejectBelowScore int

	// optionally add IPs you wish to unconditionally allow
	Whitelist []net.IP

	// optionally log all dropped http requests
	LogBlocked bool

	// optionally allow any request if there was a problem reaching iprepd
	FailOpen bool

	// optionally use non-default http client settings
	HTTPClient *http.Client
}

const fwLogPrefix = "[iprepd-firewall]"

var noEntryMsg = "non 200 status code received: 404"

// Wrap the firewall around an HTTP handler. The returned http.Handler will
// only serve requests from IPs which satisfy one or more of the following:
//  - the IP is included in the Firewall's whitelist
//  - the IP does not have an entry in iprepd (implying no violations)
//  - the IP has an entry in iprepd with a score above RejectBelowScore
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

		srcIP, err := extractIP(r)
		if err != nil {
			if fw.FailOpen {
				h.ServeHTTP(w, r)
				return
			}
			if fw.LogBlocked {
				log.Printf(
					"%s an error occurred extracting ip from request, error: %s",
					fwLogPrefix,
					err,
				)
			}
			w.WriteHeader(http.StatusForbidden)
			return
		}

		if isWhitelisted(srcIP, fw.Whitelist) {
			h.ServeHTTP(w, r)
			return
		}

		rep, err := c.GetReputation("ip", srcIP.String())
		if err != nil {
			if err.Error() == noEntryMsg || fw.FailOpen {
				h.ServeHTTP(w, r)
				return
			}
			if fw.LogBlocked {
				log.Printf(
					"%s an error occurred getting ip reputation, blocking %s, error: %s",
					fwLogPrefix,
					srcIP.String(),
					err,
				)
			}
			w.WriteHeader(http.StatusForbidden)
			return
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

		h.ServeHTTP(w, r)
		return
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

func extractIP(r *http.Request) (net.IP, error) {
	ip := net.ParseIP(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0])
	if ip != nil {
		return ip, nil
	}
	ip = net.ParseIP(strings.Split(r.RemoteAddr, ":")[0])
	if ip != nil {
		return ip, nil
	}
	return nil, errors.New("no remote ip found in request")
}
