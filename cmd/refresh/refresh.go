package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"text/template"
	"time"
)

const targetPerSearch = 800

func main() {
	intC := make(chan os.Signal, 1)
	signal.Notify(intC, os.Interrupt)

	start, err := time.Parse(time.RFC3339, os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	end := start.Add(1 * time.Hour)

	out := json.NewEncoder(os.Stdout)
	for time.Now().After(start) {
		select {
		case <-intC:
			return
		default:
		}

		keys, count, err := search(start, end)
		if err != nil && err != errTooManyResults {
			log.Fatal(err)
		}

		if min := targetPerSearch / 10; count < min {
			count = min // avoid large jumps
		}
		oldRange := end.Sub(start)
		newRange := oldRange / time.Duration(count) * targetPerSearch

		if err == errTooManyResults {
			log.Printf("[%v to %v] %d users, shrinking...",
				start.Format(time.RFC3339), end.Format(time.RFC3339), count)
			end = start.Add(newRange)
			continue
		}

		for key, uid := range keys {
			out.Encode(struct {
				ID  uint64 `json:"id"`
				Key string `json:"key"`
			}{uid, key})
		}

		log.Printf("[%v to %v] %d users, got %d keys",
			start.Format(time.RFC3339), end.Format(time.RFC3339), count, len(keys))
		newRange = (oldRange*4 + newRange) / 5 // soften steady-state swings
		start, end = end, end.Add(newRange)
	}
}

var errTooManyResults = errors.New("more than 1000 results")

func search(from, to time.Time) (keys map[string]uint64, count int, err error) {
	var after string
	var retries int
	keys = make(map[string]uint64)
	for {
		res, err := apiRequest(from, to, after)
		if err != nil {
			// Empirically, some time ranges are in a weird state where they always
			// generate an error like this:
			//   GraphQL error "Not Found"
			// Detect this and divide and conquer to skip the bad range...but as small a piece as reasonably possible.
			if strings.Contains(err.Error(), `GraphQL error "Not Found"`) && retries >= 3 {
				dur := to.Sub(from)
				if dur < time.Minute {
					// declare this range to be empty, by fiat
					log.Printf("[%v to %v] skipping range due to persistent Not Found errors", from.Format(time.RFC3339), to.Format(time.RFC3339))
					return nil, 0, nil
				}
				middle := from.Add(to.Sub(from) / 2)
				log.Printf("[%v to %v] hit persistent Not Found error, dividing range at %v", from.Format(time.RFC3339), to.Format(time.RFC3339), middle.Format(time.RFC3339))
				leftFrom, leftTo := from, middle
				rightFrom, rightTo := middle, to
				leftKeys, leftCount, err := search(leftFrom, leftTo)
				if err != nil {
					return nil, 0, err
				}
				log.Printf("[%v to %v] left half got %d keys for %v users", leftFrom.Format(time.RFC3339), leftTo.Format(time.RFC3339), len(leftKeys), leftCount)
				rightKeys, rightCount, err := search(rightFrom, rightTo)
				if err != nil {
					return nil, 0, err
				}
				log.Printf("[%v to %v] right half got %d keys for %v users", rightFrom.Format(time.RFC3339), rightTo.Format(time.RFC3339), len(rightKeys), rightCount)
				merged := make(map[string]uint64, len(leftKeys)+len(rightKeys))
				maps.Insert(merged, maps.All(leftKeys))
				maps.Insert(merged, maps.All(rightKeys))
				return merged, leftCount + rightCount, nil
			}
			if retries >= 5 {
				return nil, 0, err
			}
			retries++
			s := retries * retries * retries
			log.Printf("[%v to %v] API error: %v; sleeping %d seconds...", from.Format(time.RFC3339), to.Format(time.RFC3339), err, s)
			time.Sleep(time.Duration(s) * time.Second)
			continue
		}
		retries = 0

		if res.UserCount > 1000 {
			return nil, res.UserCount, errTooManyResults
		}

		for _, user := range res.Edges {
			for _, key := range user.Node.PublicKeys.Nodes {
				keys[key.Key] = user.Node.DatabaseID
			}
		}

		after = res.PageInfo.EndCursor
		count = res.UserCount
		if !res.PageInfo.HasNextPage {
			break
		}
	}
	return keys, count, nil
}

var client = &http.Client{Timeout: 5 * time.Second}

var token = os.Getenv("GITHUB_TOKEN")

func apiRequest(from, to time.Time, after string) (*searchResult, error) {
	buf := &strings.Builder{}
	query.Execute(buf, struct {
		From, To, After string
	}{From: from.Format(time.RFC3339), To: to.Format(time.RFC3339), After: after})
	body, _ := json.Marshal(struct {
		Query string `json:"query"`
	}{Query: buf.String()})

	r, _ := http.NewRequest("POST", "https://api.github.com/graphql", bytes.NewReader(body))
	r.Header.Set("Authorization", "bearer "+token)
	res, err := client.Do(r)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	out := &response{}
	if err := json.NewDecoder(res.Body).Decode(out); err != nil {
		return nil, err
	}
	if len(out.Errors) > 0 {
		return nil, fmt.Errorf("GraphQL error %q", out.Errors[0].Message)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status %q", res.Status)
	}

	return &out.Data.Search, nil
}

var query = template.Must(template.New("query").Parse(`
{
	search(
		type: USER
		query: "type:user created:{{ .From }}..{{ .To }}"
		first: 100
		{{ if .After }}after: "{{ .After }}"{{ end }}
	) {
		userCount
		pageInfo {
			hasNextPage
			endCursor
		}
		edges {
			node {
				... on User {
					databaseId
					publicKeys(first: 100) {
						nodes {
							key
						}
					}
				}
			}
		}
	}
}
`))

type searchResult struct {
	UserCount int `json:"userCount"`
	PageInfo  struct {
		HasNextPage bool   `json:"hasNextPage"`
		EndCursor   string `json:"endCursor"`
	} `json:"pageInfo"`
	Edges []struct {
		Node struct {
			DatabaseID uint64 `json:"databaseId"`
			PublicKeys struct {
				Nodes []struct {
					Key string `json:"key"`
				} `json:"nodes"`
			} `json:"publicKeys"`
		} `json:"node"`
	} `json:"edges"`
}

type response struct {
	Data struct {
		Search searchResult `json:"search"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}
