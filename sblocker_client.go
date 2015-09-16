package main

import (
	"fmt"
	"os"
	"bufio"
	"strings"
	"net/http"
	"net/url"
	"io/ioutil"
	"strconv"
	"flag"
	"regexp"
	"net"
)

//Config vars
var debug *string
var filter_url *string
var ans *string
var user *string
var pass *string
var v6_host = regexp.MustCompile(`^%5B([\:a-z0-9]+)\%5D\:([0-9]+)`) 
var v6_uri = regexp.MustCompile(`^^([a-z]+\:\/\/)\%5B([\:a-z0-9]+)\%5D(\:)?([0-9]+)?(\/.*)`) 
var err error

func check_tcp(host string, port string) string{
	if *debug != "no" {
		fmt.Fprintf(os.Stderr, "ERRlog: reporting query => \"" + host +":" + port + "\"\n")
		fmt.Fprintf(os.Stderr, "ERRlog: reporting url => \"" + *filter_url + "/tcp/?host=" + host + "&" + "port=" + port + "\"\n")

	}
        client := &http.Client{}
	request, err := http.NewRequest("GET", *filter_url + "/tcp/?host=" + host + "&" + "port=" + port, nil)
	request.Close = true
	request.SetBasicAuth(*user, *pass)

	resp, err := client.Do(request)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERRlog: reporting a http connection error1 => \"" + err.Error() + "\"\n")
		return "DUNO"
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERRlog: reporting a http connection error2 => \"" + err.Error() + "\"\n")
		return "DUNO"
	}

        if body != nil {
		return string(body)
        }
        return "DUNO"
}

func check(uri string) string{
	encstr := url.QueryEscape(uri)
	if *debug != "no" {
		fmt.Fprintf(os.Stderr, "ERRlog: reporting query => \"" + uri + "\"\n")
		fmt.Fprintf(os.Stderr, "ERRlog: reporting url => \"" + *filter_url + "/url/?url=" + encstr + "\"\n")

	}

        client := &http.Client{}
	request, err := http.NewRequest("GET", *filter_url + "/url/?url=" + encstr, nil)
	request.Close = true
	request.SetBasicAuth(*user, *pass)

	resp, err := client.Do(request)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERRlog: reporting a http connection error => \"" + err.Error() + "\"\n")
		return "DUNO"
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil && *debug == "no"{
		fmt.Fprintf(os.Stderr, "ERRlog: reporting body read error => \"" + err.Error() + "\"\n")
	}
        if body != nil {
		return string(body)
        }
        return "DUNO"
}

func process_request(line string) {
		lparts := strings.Split( strings.TrimRight(line, "\n"), " ")
		if len(lparts[0]) > 0 {
			if *debug != "no" {
				fmt.Fprintf(os.Stderr, "ERRlog: Request nubmer => " + lparts[0] + "\n")
			}
		}
		var answer string
		if *debug != "no" {
			fmt.Fprintf(os.Stderr, "ERRlog: request from squid => ")
			fmt.Fprintln(os.Stderr, lparts)
		}
		// First parse the url from squid
		var uri *url.URL
		uri , err = url.Parse(lparts[1])
		if (err != nil) && ( !strings.Contains(err.Error(), "hexadecimal escape in host")) {
			fmt.Fprintf(os.Stderr, err.Error() + "\n")
			fmt.Fprintf(os.Stderr, lparts[0] + " " + *ans + " error=error parsing url" + "\n")
		}

		if (err != nil) && strings.Contains(err.Error(), "hexadecimal escape in host") {
			res := v6_uri.FindStringSubmatch(lparts[1])
			if len(res) == 4 {
				answer = check(res[1] + "[" + res[2] + "]" + res[3] + res[4])
			}
			if len(res) == 6 {
				answer = check(res[1] + "[" + res[2] + "]" + res[3] + res[4] + res[5])
			}

		} else if (lparts[2] == "CONNECT") && v6_host.MatchString(lparts[1]) {
			res := v6_host.FindStringSubmatch(lparts[1])
			host := net.ParseIP(res[1])
			if host != nil {
				answer = check_tcp(net.IP.String(host),res[2])
			} else {
				answer = check_tcp(res[1],res[2])
			}
		} else if (len(uri.Opaque) > 0)   {
			// The next uri.Scheme is being exploited and used for the host string
			answer = check_tcp(uri.Scheme, uri.Opaque)
		} else if  (lparts[2] == "CONNECT"){
			//Counting on that squid will never send bougous ip:port with a connect
			host_ip := strings.Split( lparts[1], ":")
			answer = check_tcp(host_ip[0], host_ip[1])

		} else {
//                        answer = check(uri.Scheme + "://" + uri.Host + uri.Path)
			answer = check(lparts[1])
		}

		if *debug != "no" {
			fmt.Fprintf(os.Stderr, "ERRlog: reporting answer size => " + strconv.Itoa(len(answer)) + "\n")
			fmt.Fprintf(os.Stderr, "ERRlog: reporting answer => " + answer + "\n")

		}

		if strings.HasPrefix(answer, "ERR") || strings.HasPrefix(answer, "1") {
			if *debug != "no" {
				fmt.Fprintf(os.Stderr, "ERRlog: reporting answer startsWith => \"ERR\"\n")
			}
			fmt.Println(lparts[0] + " ERR rate=100")
			return
		}
		if strings.Contains(answer, "not found") || strings.HasPrefix(answer, "OK") {
			if *debug != "no" {
				fmt.Fprintf(os.Stderr, "ERRlog: reporting answer startsWith => \"OK\" or \"not found\"\n")
			}
			fmt.Println(lparts[0] + " OK")
			return
		}
		if strings.HasPrefix(answer, "DUNO") {
			if *debug != "no" {
				fmt.Fprintf(os.Stderr, "ERRlog: reporting answer startsWith => \"DUNO\"\n")
			}
			if len(*ans) > 0  {
				fmt.Println(lparts[0] + " " + *ans + " rate=101")
				return
			} else {
				fmt.Println(lparts[0] + " OK state=DUNO")
				return
			}
		}
		fmt.Println(lparts[0] + " " + *ans + " rate=102")
}

func main() {
	reader := bufio.NewReader(os.Stdin)


	fmt.Fprintf(os.Stderr, "ERRlog: hello go, running [filter_helper] (probably under squid) :D")

        debug = flag.String("d", "no", "Debug mode can be turned on by using anything else then \"no\"")
        filter_url = flag.String("http", "http://filterdb:8080/sb/01", "Base path where for the DB")
        user = flag.String("user", "admin", "Basic auth username for server authentication")
        pass = flag.String("pass", "admin", "Basic auth password for server authentication")

        ans = flag.String("ans", "OK", "Default answer For cases of Errors")

        flag.Parse()

	if err != nil {
		fmt.Println("error:", err)
	}
	if *debug != "no" {
		fmt.Fprintf(os.Stderr, "ERRlog: Config Variables:")
		fmt.Fprintf(os.Stderr, "ERRlog: DB http url: => " + *filter_url)
		fmt.Fprintf(os.Stderr, "ERRlog: Debug: => " + *debug)
	}


    for {
        line, err := reader.ReadString('\n')

        if err != nil {
            // You may check here if err == io.EOF
            break
        }

		go process_request(line)

    }
}

