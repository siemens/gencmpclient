cd ./test/recipes/80-test_cmp_http_data/Mock
# gdb --args \
../../../../cmpClient \
	-config ../test.cnf \
	-section "Mock" -cmd cr \
	-rats \
	-tpmkd_tokenname  "tcg-key-req" \
	-tpmkd_tokencfgpath  "../../../../atg/atglib-key-attestation-demo/token-cfg.json" \
	-tpmkd_plugincfgpath  "../../../../atg/atglib-key-attestation-demo/plugins.json" \
	-tpmkd_nonce test_nonce_1234 \
	-atcha_tokenname  "tcg-key-chal" \
	-atcha_tokencfgpath  "../../../../atg/atglib-key-attestation-demo/token-cfg.json" \
	-atcha_plugincfgpath  "../../../../atg/atglib-key-attestation-demo/plugins.json" \
	-atcha_nonce test_nonce_5678

