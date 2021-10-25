# login detection
curl https://httpbin.webbots.page/anything/raw --data-raw '{"username": "bc"}' -H 'content-type:application/json' # pass
curl https://httpbin.webbots.page/anything/raw-caps --data-raw '{"USERNAME": "bc"}' -H 'content-type:application/json' # pass
curl https://httpbin.webbots.page/anything/form-www-url -d 'username=bob' -H "Content-Type: application/x-www-form-urlencoded" # pass
curl https://httpbin.webbots.page/anything/form-www-url -F 'username=bob' # FAIL - This fails because of the multi-form post content-type (I think).

# card detection
curl https://httpbin.webbots.page/anything/raw --data-raw '{"cvv": "123"}' -H 'content-type:application/json' # pass

# robots.txt disallow detection
curl https://httpbin.webbots.page/anything/labs/1 # pass

