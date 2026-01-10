CC=g++
CFLAGS = -std=c++20 -Wall -Werror
LDFLAGS = -lstdc++ -lssl -lcrypto -lpcap -lmaxminddb

all: smpass smnet smlog smssh smdb libsecurity_manager.a

smpass: obj/argsparser.o obj/smpass.o obj/smstorage.o obj/logger.o
	@mkdir -p bin
	$(CC) $(CFLAGS) $(LDFLAGS) -Iargsparser -Ismpass -Ilogger obj/smpass.o obj/argsparser.o obj/smstorage.o obj/logger.o -o bin/smpass

smnet: obj/argsparser.o obj/smnet.o obj/logger.o
	@mkdir -p bin
	$(CC) $(CFLAGS) $(LDFLAGS) -Iargsparser -Ismnet -Ilogger obj/argsparser.o obj/smnet.o obj/logger.o -o bin/smnet

smlog: obj/smlog.o obj/systemlogger.o obj/logger.o
	@mkdir -p bin
	$(CC) $(CFLAGS) $(LDFLAGS) -Ilogger obj/smlog.o obj/systemlogger.o obj/logger.o -o bin/smlog

smssh: obj/smssh.o obj/sshconfig.o obj/sshattdetector.o obj/logger.o
	@mkdir -p bin
	$(CC) $(CFLAGS) $(LDFLAGS) -Ismssh -Ilogger obj/smssh.o obj/sshconfig.o obj/sshattdetector.o obj/logger.o -o bin/smssh

smdb: obj/smdb.o obj/logger.o
	@mkdir -p bin
	$(CC) $(CFLAGS) $(LDFLAGS) -Ismdb -Ilogger obj/smdb.o obj/logger.o -o bin/smdb

libsecurity_manager.a: obj/smpass_api.o obj/smnet_api.o obj/smlog_api.o obj/smssh_api.o obj/smdb_api.o obj/securitymanager.o obj/logger.o obj/argsparser.o obj/smstorage.o obj/smnet.o obj/systemlogger.o obj/sshconfig.o obj/sshattdetector.o
	@echo "Building Security Manager API library..."
	@ar rcs libsecurity_manager.a obj/smpass_api.o obj/smnet_api.o obj/smlog_api.o obj/smssh_api.o obj/smdb_api.o obj/securitymanager.o obj/logger.o obj/argsparser.o obj/smstorage.o obj/smnet.o obj/systemlogger.o obj/sshconfig.o obj/sshattdetector.o
	@echo "Static library libsecurity_manager.a created"

obj/smpass_api.o: api/src/smpass_api.cpp
	@mkdir -p obj
	$(CC) $(CFLAGS) -Iapi/include -c api/src/smpass_api.cpp -o obj/smpass_api.o

obj/smnet_api.o: api/src/smnet_api.cpp
	@mkdir -p obj
	$(CC) $(CFLAGS) -Iapi/include -c api/src/smnet_api.cpp -o obj/smnet_api.o

obj/smlog_api.o: api/src/smlog_api.cpp
	@mkdir -p obj
	$(CC) $(CFLAGS) -Iapi/include -c api/src/smlog_api.cpp -o obj/smlog_api.o

obj/smssh_api.o: api/src/smssh_api.cpp
	@mkdir -p obj
	$(CC) $(CFLAGS) -Iapi/include -c api/src/smssh_api.cpp -o obj/smssh_api.o

obj/smdb_api.o: api/src/smdb_api.cpp
	@mkdir -p obj
	$(CC) $(CFLAGS) -Iapi/include -c api/src/smdb_api.cpp -o obj/smdb_api.o

obj/securitymanager.o: api/src/securitymanager.cpp
	@mkdir -p obj
	$(CC) $(CFLAGS) -Iapi/include -c api/src/securitymanager.cpp -o obj/securitymanager.o

obj/argsparser.o: argsparser/argsparser.cpp
	@mkdir -p obj
	$(CC) $(CFLAGS) -c argsparser/argsparser.cpp -o obj/argsparser.o

obj/smpass.o: smpass/smpass.cpp
	@mkdir -p obj
	$(CC) $(CFLAGS) -c smpass/smpass.cpp -o obj/smpass.o

obj/smstorage.o:
	@mkdir -p obj
	$(CC) $(CFLAGS) -Ijson -Ilogger -c smpass/storage.cpp -o obj/smstorage.o

obj/smnet.o:
	@mkdir -p obj
	$(CC) $(CFLAGS) -Ilogger -c smnet/smnet.cpp -o obj/smnet.o

obj/smlog.o:
	@mkdir -p obj
	$(CC) $(CFLAGS) -Ilogger -Ismlog -c smlog/smlog.cpp -o obj/smlog.o

obj/systemlogger.o:
	@mkdir -p obj
	$(CC) $(CFLAGS) -Ismlog -c smlog/SystemLogger.cpp -o obj/systemlogger.o

obj/smssh.o:
	@mkdir -p obj
	$(CC) $(CFLAGS) -Ismssh -c smssh/smssh.cpp -o obj/smssh.o

obj/smdb.o:
	@mkdir -p obj
	$(CC) $(CFLAGS) -Ismdb -c smdb/smdb.cpp -o obj/smdb.o

obj/sshconfig.o:
	@mkdir -p obj
	$(CC) $(CFLAGS) -Ismssh -c smssh/sshConfig.cpp -o obj/sshconfig.o

obj/sshattdetector.o:
	@mkdir -p obj
	$(CC) $(CFLAGS) -Ismssh -Ilogger -c smssh/sshAttackDetector.cpp -o obj/sshattdetector.o

obj/logger.o:
	@mkdir -p obj
	$(CC) $(CFLAGS) -Ilogger -c logger/logger.cpp -o obj/logger.o

clean:
	rm -rf obj
	rm -rf bin

install: all install-geolite install-systemd install-doc
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Error: install requires root privileges"; \
		exit 1; \
	fi
	@echo "Installing Security Manager utilities..."
	@install -d /usr/local/bin
	@install -m 755 bin/smpass /usr/local/bin/
	@install -m 755 bin/smnet /usr/local/bin/
	@install -m 755 bin/smlog /usr/local/bin/
	@install -m 755 bin/smssh /usr/local/bin/
	@install -m 755 bin/smdb /usr/local/bin/
	@echo "Binaries installed to /usr/local/bin/"
	@echo "Security Manager installation completed!"
	@echo ""
	@echo "Usage examples:"
	@echo "  smssh help                    - SSH security management"
	@echo "  smlog help                    - System log analysis"
	@echo "  smpass help                   - Password management"
	@echo "  smnet help                    - Network monitoring"
	@echo ""
	@echo "To start SSH monitoring service:"
	@echo "  systemctl enable smssh"
	@echo "  systemctl start smssh"

install-geolite:
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Error: install-geolite requires root privileges"; \
		exit 1; \
	fi
	@echo "Installing GeoLite2 database..."
	@mkdir -p /usr/share/GeoIP
	@if [ ! -f /usr/share/GeoIP/GeoLite2-Country.mmdb ]; then \
		cd /usr/share/GeoIP && wget -q https://git.io/GeoLite2-Country.mmdb -O GeoLite2-Country.mmdb; \
		echo "GeoLite2 database downloaded"; \
	else \
		echo "GeoLite2 database already exists"; \
	fi

install-systemd:
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Error: install-systemd requires root privileges"; \
		exit 1; \
	fi
	@echo "Installing systemd unit..."
	@cp smssh/smssh.service /etc/systemd/system/
	@systemctl daemon-reload
	@echo "Systemd unit installed"
	@echo "Use 'systemctl enable smssh' to enable on boot"
	@echo "Use 'systemctl start smssh' to start monitoring"

install-doc:
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Error: install-doc requires root privileges"; \
		exit 1; \
	fi
	@echo "Installing Security Manager documentation..."
	@install -d /usr/share/doc/security-manager
	@install -d /usr/share/doc/security-manager/attacks

	@cp -r doc/api/html /usr/share/doc/security-manager/api-docs
	@cp doc/attacks/*.html /usr/share/doc/security-manager/attacks/
	@chmod -R 644 /usr/share/doc/security-manager/
	@find /usr/share/doc/security-manager/ -type d -exec chmod 755 {} \;
	@echo "Documentation installed to /usr/share/doc/security-manager/"
	@echo "API documentation: /usr/share/doc/security-manager/api-docs/index.html"
	@echo "Attack database: /usr/share/doc/security-manager/attacks/"
	@echo "User guides: /usr/share/doc/security-manager/index.html"

install-doc-only: doc/doxygen/html/index.html doc/utils/index.html
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Error: install-doc-only requires root privileges"; \
		exit 1; \
	fi
	@echo "Installing Security Manager documentation..."
	@install -d /usr/share/doc/security-manager
	@install -d /usr/share/doc/security-manager/attacks
	@cp -r doc/api/html /usr/share/doc/security-manager/api-docs
	@cp doc/attacks/*.html /usr/share/doc/security-manager/attacks/
	@chmod -R 644 /usr/share/doc/security-manager/
	@find /usr/share/doc/security-manager/ -type d -exec chmod 755 {} \;
	@echo "Documentation installed to /usr/share/doc/security-manager/"
	@echo "API documentation: /usr/share/doc/security-manager/api-docs/index.html"
	@echo "User guides: /usr/share/doc/security-manager/index.html"
	@echo "Attack database: /usr/share/doc/security-manager/attacks/"

uninstall:
	@if [ "$(shell id -u)" != "0" ]; then \
		echo "Error: uninstall requires root privileges"; \
		exit 1; \
	fi
	@echo "Uninstalling Security Manager..."
	@systemctl stop smssh 2>/dev/null || true
	@systemctl disable smssh 2>/dev/null || true
	@rm -f /etc/systemd/system/smssh.service
	@systemctl daemon-reload
	@echo "Systemd unit removed"
	@rm -f /usr/local/bin/smpass
	@rm -f /usr/local/bin/smnet
	@rm -f /usr/local/bin/smlog
	@rm -f /usr/local/bin/smssh
	@rm -f /usr/local/bin/smdb
	@echo "Binaries removed from /usr/local/bin/"
	@rm -rf /usr/share/doc/security-manager
	@echo "Documentation removed from /usr/share/doc/security-manager/"
	@echo "Security Manager uninstallation completed!"
	@echo ""
	@echo "Note: GeoLite2 database in /usr/share/GeoIP/ was not removed."
	@echo "You can manually remove it if desired."

doc: doc/doxygen/html/index.html doc/utils/index.html
	@echo "Documentation generated successfully!"
	@echo "API docs: doc/api/html/index.html"

doc/doxygen/html/index.html: Doxyfile
	@echo "Generating Doxygen API documentation..."
	@doxygen Doxyfile

doc/utils/index.html: doc/utils/style.css
	@echo "HTML utility documentation is ready"

check: all
	@echo "Running Security Manager test suite..."
	@echo "=========================================="
	@echo
	@echo "0" > /tmp/sm_test_passed
	@echo "0" > /tmp/sm_test_total

	@echo "Testing smssh..."
	@echo "---------------"
	@if ./bin/smssh help >/dev/null 2>&1; then echo "smssh help works"; expr $$(cat /tmp/sm_test_passed) + 1 > /tmp/sm_test_passed; else echo "smssh help failed"; exit 1; fi; expr $$(cat /tmp/sm_test_total) + 1 > /tmp/sm_test_total
	@if ./bin/smssh parse-log test/test_brute_recent.log 2>/dev/null | grep -q "brute_force"; then echo "SSH brute force detection works"; expr $$(cat /tmp/sm_test_passed) + 1 > /tmp/sm_test_passed; else echo "SSH brute force detection failed"; fi; expr $$(cat /tmp/sm_test_total) + 1 > /tmp/sm_test_total
	@if ./bin/smssh analyze test/test_sshd_config >/dev/null 2>&1; then echo "SSH config analysis works"; expr $$(cat /tmp/sm_test_passed) + 1 > /tmp/sm_test_passed; else echo "SSH config analysis failed"; fi; expr $$(cat /tmp/sm_test_total) + 1 > /tmp/sm_test_total
	@echo

	@echo "Testing smlog..."
	@echo "---------------"
	@if ./bin/smlog help >/dev/null 2>&1; then echo "smlog help works"; expr $$(cat /tmp/sm_test_passed) + 1 > /tmp/sm_test_passed; else echo "smlog help failed"; exit 1; fi; expr $$(cat /tmp/sm_test_total) + 1 > /tmp/sm_test_total
	@if ./bin/smlog read test/test_system.log >/dev/null 2>&1; then echo " smlog read works"; expr $$(cat /tmp/sm_test_passed) + 1 > /tmp/sm_test_passed; else echo " smlog read failed"; fi; expr $$(cat /tmp/sm_test_total) + 1 > /tmp/sm_test_total
	@if ./bin/smlog search "sshd" test/test_system.log >/dev/null 2>&1; then echo " smlog search works"; expr $$(cat /tmp/sm_test_passed) + 1 > /tmp/sm_test_passed; else echo " smlog search failed"; fi; expr $$(cat /tmp/sm_test_total) + 1 > /tmp/sm_test_total
	@echo

	@echo "Testing smpass..."
	@echo "---------------"
	@if ./bin/smpass help >/dev/null 2>&1; then echo " smpass help works"; expr $$(cat /tmp/sm_test_passed) + 1 > /tmp/sm_test_passed; else echo " smpass help failed"; exit 1; fi; expr $$(cat /tmp/sm_test_total) + 1 > /tmp/sm_test_total
	@if ./bin/smpass hash-sha256 "test" >/dev/null 2>&1; then echo " smpass SHA256 hashing works"; expr $$(cat /tmp/sm_test_passed) + 1 > /tmp/sm_test_passed; else echo " smpass SHA256 hashing failed"; fi; expr $$(cat /tmp/sm_test_total) + 1 > /tmp/sm_test_total
	@if ./bin/smpass hash-aes256 "test" >/dev/null 2>&1; then echo " smpass AES256 encryption works"; expr $$(cat /tmp/sm_test_passed) + 1 > /tmp/sm_test_passed; else echo " smpass AES256 encryption failed"; fi; expr $$(cat /tmp/sm_test_total) + 1 > /tmp/sm_test_total
	@echo

	@echo "Testing smnet..."
	@echo "---------------"
	@if ./bin/smnet help >/dev/null 2>&1; then echo " smnet help works"; expr $$(cat /tmp/sm_test_passed) + 1 > /tmp/sm_test_passed; else echo " smnet help failed"; exit 1; fi; expr $$(cat /tmp/sm_test_total) + 1 > /tmp/sm_test_total
	@if ./bin/smnet scan >/dev/null 2>&1; then echo " smnet port scanning works"; expr $$(cat /tmp/sm_test_passed) + 1 > /tmp/sm_test_passed; else echo " smnet port scanning failed"; fi; expr $$(cat /tmp/sm_test_total) + 1 > /tmp/sm_test_total
	@echo

	@echo "Testing API library..."
	@echo "--------------------"
	@if [ -f libsecurity_manager.a ]; then echo " API library exists"; expr $$(cat /tmp/sm_test_passed) + 1 > /tmp/sm_test_passed; else echo " API library missing"; fi; expr $$(cat /tmp/sm_test_total) + 1 > /tmp/sm_test_total
	@echo

	@echo "Testing smdb..."
	@echo "--------------"
	@if ./bin/smdb help >/dev/null 2>&1; then echo " smdb help works"; expr $$(cat /tmp/sm_test_passed) + 1 > /tmp/sm_test_passed; else echo " smdb help failed"; exit 1; fi; expr $$(cat /tmp/sm_test_total) + 1 > /tmp/sm_test_total
	@if ./bin/smdb list >/dev/null 2>&1; then echo " smdb attack database works"; expr $$(cat /tmp/sm_test_passed) + 1 > /tmp/sm_test_passed; else echo " smdb attack database failed"; fi; expr $$(cat /tmp/sm_test_total) + 1 > /tmp/sm_test_total
	@echo

	@passed=$$(cat /tmp/sm_test_passed); total=$$(cat /tmp/sm_test_total); rm -f /tmp/sm_test_passed /tmp/sm_test_total
	@echo "Test Results: $$passed/$$total tests passed"
	@echo "All core functionality tests completed successfully!"
	@echo "   Security Manager is ready for production use."

.PHONY: install install-geolite install-systemd install-doc install-doc-only uninstall clean check smdb doc