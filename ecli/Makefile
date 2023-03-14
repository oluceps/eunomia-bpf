LIBEUNOMIA := ../bpf-loader/build/lib/Release/libeunomia.a

.PHONY: build
build: $(LIBEUNOMIA)
	cargo build --release

$(LIBEUNOMIA):
	$(MAKE) -C ../bpf-loader install

install: $(LIBEUNOMIA) ## install the package to the `INSTALL_LOCATION`
	rm -rf target/
	cargo build --release
	mkdir -p ~/.eunomia/bin
	cp ./target/release/ecli ~/.eunomia/bin/ecli

install-deps:
	sudo apt install libssl-dev
	sudo apt install pkg-config
	mkdir -p ~/bin/openapitools
	curl https://raw.githubusercontent.com/OpenAPITools/openapi-generator/master/bin/utils/openapi-generator-cli.sh > ~/bin/openapitools/openapi-generator-cli
	chmod u+x ~/bin/openapitools/openapi-generator-cli
	cd api && ~/bin/openapitools/openapi-generator-cli generate -g rust-server -i apis.yaml
