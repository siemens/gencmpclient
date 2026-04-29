# start CMP mock server

```bash
cd ~/git/gencmpclient/test/recipes/80-test_cmp_http_data/Mock
openssl cmp -config server.cnf
```

# do GENM
cd ~/git/gencmpclient/test/recipes/80-test_cmp_http_data/Mock
../../../../cmpClient -config ../test.cnf -section "Mock" -cmd genm

# do CR
cd ~/git/gencmpclient/test/recipes/80-test_cmp_http_data
../../../../cmpClient -config ../test.cnf -section "Mock" -cmd cr
```

