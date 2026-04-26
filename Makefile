poxdir ?= /opt/pox/

# Complete the makefile as you prefer!
topo:
	@echo "starting the topology! (i.e., running mininet)"
	@echo "cleaning stale mininet state before startup"
	-@sudo mn -c >/dev/null 2>&1 || true
	sudo python ./topology/topology.py

app:
	@echo "starting the baseController!"
	# Copy your controller to the POX folder
	cp applications/controller/* $(poxdir)ext/
	# Copy nfv click functions to the pox controller folder
	cp applications/nfv/*.click $(poxdir)ext/
	# Run controller that setups normal switches and CLICK nodes
	sudo python /opt/pox/pox.py baseController

test:
	@set -e; \
	sudo -v; \
	echo "1. Cleaning stale controller/mininet/click state"; \
	$(MAKE) clean >/dev/null 2>&1 || true; \
	cleanup() { $(MAKE) clean >/dev/null 2>&1 || true; }; \
	trap cleanup EXIT INT TERM; \
	echo "2. Starting controller in background"; \
	# Run the app target in the background so it doesn't block the tests
	$(MAKE) app >/tmp/pox-test.log 2>&1 & \
	sleep 5; \
	echo "3. Running automated topology tests"; \
	sudo python ./topology/topology_test.py; \
	echo "4. Shutting down and flushing reports"

clean:
	@echo "project files removed from pox directory!"
	# Remove files from ext dir in pox
	rm -f $(poxdir)ext/baseController.py $(poxdir)ext/click_wrapper.py $(poxdir)ext/*.click
	# Kill controller
	@# use the regexp trick to not match grep itself. Try graceful stop first, then force kill if needed.
	-@pids=$$(ps -ef | grep '[p]ox.py' | awk '{print $$2}'); \
	if [ -n "$$pids" ]; then sudo kill -TERM $$pids 2>/dev/null || true; fi
	-@sleep 1
	-@pids=$$(ps -ef | grep '[p]ox.py' | awk '{print $$2}'); \
	if [ -n "$$pids" ]; then sudo kill -KILL $$pids 2>/dev/null || true; fi
	# Clean mininet
	sudo mn -c
	# Kill click processes
	-@sudo killall -SIGTERM click 2>/dev/null || true

