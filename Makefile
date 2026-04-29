poxdir ?= /opt/pox/

# Complete the makefile as you prefer!
topo:
	@echo "starting the topology! (i.e., running mininet)"
	@echo "cleaning stale mininet state before startup"
	-@sudo mn -c >/dev/null 2>&1 || true
	sudo python ./topology/topology.py

app:
	mkdir -p results logs
	sudo echo "" > /tmp/lb1.stderr
	sudo echo "" > /tmp/lb1.stdout
	@echo "starting the baseController!"
	# Copy your controller to the POX folder
	cp applications/controller/* $(poxdir)ext/
	# Copy nfv click functions to the pox controller folder
	cp applications/nfv/*.click $(poxdir)ext/
	# Run controller that setups normal switches and CLICK nodes
	sudo python /opt/pox/pox.py baseController

test:
	@set -e; \
	stty sane 2>/dev/null || true; \
	stty onlcr 2>/dev/null || true; \
	sudo -v; \
	echo "1. Cleaning stale controller/mininet/click state"; \
	$(MAKE) clean >/dev/null 2>&1 || true; \
	stty sane 2>/dev/null || true; \
	stty onlcr 2>/dev/null || true; \
	cleanup() { $(MAKE) stop >/dev/null 2>&1 || true; stty sane 2>/dev/null || true; stty onlcr 2>/dev/null || true; }; \
	trap cleanup EXIT INT TERM; \
	echo "2. Starting controller in background"; \
	$(MAKE) app >/tmp/pox-test.log 2>&1 & \
	sleep 5; \
	echo "3. Running automated topology tests"; \
	sudo python -m results.topology_test; \
	echo "4. Shutting down and flushing reports"

stop:
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

clean: stop
	@echo "project files removed from pox directory!"
	# Remove files from ext dir in pox
	rm -f $(poxdir)ext/baseController.py $(poxdir)ext/click_wrapper.py $(poxdir)ext/*.click
	# Clean result/log files 
	-@echo "Cleaning result and log files"
	-@sudo rm -f /results/*.report /results/*.err 2>/dev/null || true
	-@sudo rm -f /logs/* 2>/dev/null || true
	-@rm -f results/*.report results/*.err 2>/dev/null || true
	-@rm -f logs/* 2>/dev/null || true

