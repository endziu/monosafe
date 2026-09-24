.PHONY: build deploy test test-browser clear

build:
	mkdir -p dist
	cp monosafe.html dist/index.html
	cp monosafe.html dist/monosafe.html
	cp CNAME dist/CNAME

deploy: build
	surge dist/ https://monosafe.surge.sh

test:
	node --test tests/*.test.mjs

test-browser:
	npm run test:browser

clear:
	rm -f dist/index.html dist/monosafe.html dist/CNAME
	rmdir dist 2>/dev/null || true
