/*
Copyright 2015 Google Inc. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

//App Engine app for creating and saving computer generated geometric patterns
package webpatterns

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"appengine"
	"appengine/datastore"
	"appengine/user"

	"github.com/Thesandlord/geopattern"
	"github.com/gorilla/mux"
	"github.com/qedus/nds"
)

//The maximum number of pictures that can be shown in a single row in our frontend.
const numObjects = 6

type User struct {
	Name  string
	Email string
	Key   *datastore.Key
}

var (
	indexTmpl   = template.Must(template.New("index.html").ParseFiles("templates/index.html"))
	accountTmpl = template.Must(template.New("account.html").ParseFiles("templates/account.html"))
)

func init() {
	r := mux.NewRouter()

	//Handle the routes
	r.Handle("/", errorHandler(renderIndex)).Methods("GET")
	r.Handle("/", errorHandler(renderImage)).Methods("POST")

	r.Handle("/saved/{cursor}", errorHandler(savedImages)).Methods("GET")
	r.Handle("/saved/", errorHandler(savedImages)).Methods("GET")

	r.Handle("/recent/{cursor}", errorHandler(recentImages)).Methods("GET")
	r.Handle("/recent/", errorHandler(recentImages)).Methods("GET")

	r.Handle("/account/", errorHandler(renderAccount)).Methods("GET")
	r.Handle("/account/", errorHandler(updateAccount)).Methods("POST")

	r.Handle("/login/", errorHandler(login)).Methods("GET")
	r.Handle("/logout/", errorHandler(logout)).Methods("GET")

	http.Handle("/", r)

}

func login(w http.ResponseWriter, r *http.Request) error {
	c := appengine.NewContext(r)
	if u := user.Current(c); u == nil {
		url, err := user.LoginURL(c, r.URL.String())
		if err != nil {
			return fmt.Errorf("Logging In: %v", err)
		}
		//Go to login URL
		w.Header().Set("Location", url)
	} else {
		//Already Logged in, redirect to home page
		w.Header().Set("Location", "/")
	}

	w.WriteHeader(http.StatusFound)
	return nil
}

func logout(w http.ResponseWriter, r *http.Request) error {
	c := appengine.NewContext(r)
	if u := user.Current(c); u != nil {
		url, err := user.LogoutURL(c, "/")
		if err != nil {
			return fmt.Errorf("Logging Out: %v", err)
		}
		//Go to Logout URL
		w.Header().Set("Location", url)
	} else {
		//Already logged out, redirect to homepage
		w.Header().Set("Location", "/")
	}

	w.WriteHeader(http.StatusFound)
	return nil
}

//Get User Info from the datastore
func getUser(c appengine.Context) (*User, error) {
	var u User
	if x := user.Current(c); x != nil { //We are logged in
		//Create key using the User's email
		k := datastore.NewKey(c, "User", x.Email, 0, nil)
		if err := nds.Get(c, k, &u); err == datastore.ErrNoSuchEntity { //User not found, create new entity
			u.Email = x.Email
			u.Name = u.Email
			u.Key = k
			if _, err := nds.Put(c, k, &u); err != nil { //Somehow there was an error creating the User, return it!
				return nil, fmt.Errorf("Adding user to Datastore: %v", err)
			}
			//Other error
		} else if err != nil {
			return nil, fmt.Errorf("Getting user from Datastore: %v", err)
		}
	}
	return &u, nil
}

func renderIndex(w http.ResponseWriter, r *http.Request) error {
	u, err := getUser(appengine.NewContext(r))

	if err != nil {
		return fmt.Errorf("Getting User from Datastore: %v", err)
	}

	if err := indexTmpl.Execute(w, u); err != nil {
		return fmt.Errorf("Index Creation: %v", err)
	}

	return nil
}

//Create an SVG from POSTed data
func renderImage(w http.ResponseWriter, r *http.Request) error {
	i := geopattern.Pattern{
		Phrase:    r.FormValue("Phrase"),
		Generator: r.FormValue("Generator"),
		Color:     r.FormValue("Color"),
	}

	t := r.FormValue("Type")

	//Use our ImageData object to generate the image
	p := geopattern.Base64String(i)

	//Save image
	if t == "Save" && i.Phrase != "" && i.Color != "" { //Only Save images that have phrase and color fields defined
		//Get the user to use as the parent key for the saved image
		c := appengine.NewContext(r)
		u, err := getUser(c)
		if err != nil {
			return fmt.Errorf("Getting User from Datastore: %v", err)
		}
		k := datastore.NewIncompleteKey(c, "Image", u.Key) //Use the user's key as an ancestor for this image's key
		if _, err := nds.Put(c, k, &i); err != nil {
			return fmt.Errorf("Saving Image Data to Datastore: %v", err)
		}
	}

	fmt.Fprintf(w, p)
	return nil
}

func savedImages(w http.ResponseWriter, r *http.Request) error {
	c := appengine.NewContext(r)

	u, err := getUser(c)
	if err != nil {
		return fmt.Errorf("Getting User from Datastore: %v", err)
	}

	v := mux.Vars(r)

	q := datastore.NewQuery("Image").Ancestor(u.Key) //Get images from the user

	n, err := datastore.DecodeCursor(v["cursor"])
	if err == nil {
		q = q.Start(n)
	}

	return images(w, c, q, n)
}

func recentImages(w http.ResponseWriter, r *http.Request) error {
	c := appengine.NewContext(r)

	v := mux.Vars(r)

	q := datastore.NewQuery("Image") //Get images from all users

	n, err := datastore.DecodeCursor(v["cursor"])
	if err == nil {
		q = q.Start(n)
	}

	return images(w, c, q, n)
}

func images(w http.ResponseWriter, c appengine.Context, q *datastore.Query, n datastore.Cursor) error {
	next := true             //Informs client if there is more data
	prev := n.String() != "" //Informs client if there is previous data

	query := q.Run(c) //Run the query

	var images []geopattern.Pattern //Slice to hold all the images

	for i := 0; i < numObjects; i++ {
		var img geopattern.Pattern
		_, err := query.Next(&img)

		if err == datastore.Done {
			next = false //Does not have any more data
			break
		} else if err != nil {
			return fmt.Errorf("Getting Images from Datastore: %v", err)
		}

		images = append(images, img)
	}

	nc, err := query.Cursor()
	if err != nil {
		return fmt.Errorf("Creating Next Cursor: %v", err)
	}

	//If the datastore did not respond "done", check and make sure there really is more data.
	//This can happen is the number of pictures in the datastore is divisible by numObjects
	if next {
		_, err := query.Next(nil)
		next = err == nil //If we got an error, then there is no more data, so set next to false
	}

	var svgs []string //Slice of SVGs to send out

	for _, i := range images {
		svgs = append(svgs, geopattern.Base64String(i))
	}

	output := struct {
		Cursors []string
		SVGs    []string
		Prev    bool
		Next    bool
	}{
		[]string{n.String(), nc.String()},
		svgs,
		prev,
		next,
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(output) //Convert to JSON for outputing
	if err != nil {
		return fmt.Errorf("Converting Images to JSON: %v", err)
	}
	return nil
}

func renderAccount(w http.ResponseWriter, r *http.Request) error {
	u, err := getUser(appengine.NewContext(r))

	if err != nil {
		return fmt.Errorf("Getting User from Datastore: %v", err)
	}

	if err := accountTmpl.Execute(w, u); err != nil {
		return fmt.Errorf("Rendering HTML: %v", err)
	}

	return nil
}

func updateAccount(w http.ResponseWriter, r *http.Request) error {
	c := appengine.NewContext(r)

	//Get User from datastore, to ensure the client can't modify the email
	u, err := getUser(c)

	if err != nil {
		return fmt.Errorf("Getting User from Datastore: %v", err)
	}

	//Get the name from the POST request
	u.Name = r.FormValue("name")

	if _, err := nds.Put(c, u.Key, u); err != nil { //There was an error saving the User
		return fmt.Errorf("Saving User Data: %v", err)
	}

	//Refresh page
	w.Header().Set("Location", r.URL.String())
	w.WriteHeader(http.StatusFound)
	return nil
}

type errorHandler func(http.ResponseWriter, *http.Request) error

func (h errorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := h(w, r); err != nil {
		log.Print(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
