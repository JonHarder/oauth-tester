package admin

import (
	"fmt"
	"net/http"
)

var indexHtml string = `
<!DOCTYPE html>
<html>
  <body>
    <ul>
      <li><a href='/admin/users'>Users</a></li>
      <li><a href='/admin/applications'>Applications</a></li>
    </ul>
  </body>
</html>
`

func AdminIndex(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, indexHtml)
}
