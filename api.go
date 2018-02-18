package main

import (
	"net"
	"net/http"
	"os"
	"reflect"
	"syscall"
	"unsafe"

	"github.com/ant0ine/go-json-rest/rest"
	"github.com/pkg/errors"
)

const (
	ApiUrlInfo             = "/info"
	ApiUrlInventoryRefresh = "/inventory_refresh"
)

const menderSocket = "/tmp/mender.socket"

type API struct {
	m Controller
}

func NewAPI(m Controller) *API {
	return &API{m: m}
}

func (a *API) Middleware(handler rest.HandlerFunc) rest.HandlerFunc {
	return func(w rest.ResponseWriter, req *rest.Request) {
		conn := getUnixConn(w.(http.ResponseWriter))
		cred, err := getCredentials(conn)
		if err != nil {
			rest.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		req.Env["cred"] = cred

		handler(w, req)
	}
}

func (a *API) GetInfo(w rest.ResponseWriter, req *rest.Request) {
	type Info struct {
		IsAuthorized bool
		HasUpgrade   bool
		CurrentState string
	}

	hasUpgrade, err := a.m.HasUpgrade()
	if err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	info := &Info{
		IsAuthorized: a.m.IsAuthorized(),
		HasUpgrade:   hasUpgrade,
		CurrentState: a.m.GetCurrentState().Id().String(),
	}

	w.WriteJson(info)
}

func (a *API) InventoryRefresh(w rest.ResponseWriter, req *rest.Request) {
	cred := req.Env["cred"].(*syscall.Ucred)
	if cred.Uid != 0 {
		rest.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	err := a.m.InventoryRefresh()
	if err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (a *API) Run() error {
	router, err := rest.MakeRouter(
		rest.Get(ApiUrlInfo, a.GetInfo),
		rest.Post(ApiUrlInventoryRefresh, a.InventoryRefresh),
	)
	if err != nil {
		return err
	}

	api := rest.NewApi()
	api.Use(rest.MiddlewareSimple(a.Middleware))
	api.SetApp(router)

	err = os.Remove(menderSocket)
	if err != nil {
		return errors.Wrapf(err, "Failed to remove mender socket")
	}

	unixListener, err := net.Listen("unix", menderSocket)
	if err != nil {
		return err
	}

	server := http.Server{
		Handler: api.MakeHandler(),
	}

	return server.Serve(unixListener)
}

func getUnixConn(w http.ResponseWriter) *net.UnixConn {
	rw := reflect.Indirect(reflect.ValueOf(w))
	rw = reflect.Indirect(rw.FieldByName("ResponseWriter").Elem())
	conn := rw.FieldByName("conn")
	conn = reflect.Indirect(conn)
	rwc := conn.FieldByName("rwc")

	netConnPtr := (*net.Conn)(unsafe.Pointer(rwc.UnsafeAddr()))
	unixConnPtr := (*netConnPtr).(*net.UnixConn)

	return unixConnPtr
}

func getCredentials(conn *net.UnixConn) (*syscall.Ucred, error) {
	f, err := conn.File()
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return syscall.GetsockoptUcred(int(f.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
}
