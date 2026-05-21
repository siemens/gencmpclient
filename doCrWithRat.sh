cd ~/git/gencmpclient/test/recipes/80-test_cmp_http_data/Mock
# gdb --args \
../../../../cmpClient \
	-config ../test.cnf \
	-section "Mock" -cmd cr \
	-rats \
	-tpmkd_tokenname  "tcg-key-req" \
	-tpmkd_tokencfgpath  "token-cfg.json" \
	-tpmkd_plugincfgpath  "plugins.json" \
	-tpmkd_nonce test_nonce_1234 \
	-atcha_tokenname  "tcg-key-chal" \
	-atcha_tokencfgpath  "token-cfg.json" \
	-atcha_plugincfgpath  "plugins.json" \
	-atcha_nonce test_nonce_5678

