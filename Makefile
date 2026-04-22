poxdir ?= /opt/pox/

# Complete the makefile as you prefer!
topo:
	@echo "starting the topology! (i.e., running mininet)"
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
	
	@echo "2. Starting controller in background"
	# Run the app target in the background so it doesn't block the tests
	$(MAKE) app & sleep 3
	@echo "3. Running automated topology tests"
	sudo python ./topology/topology_test.py
	@echo "4. Shutting down and flushing reports"
	$(MAKE) clean

clean:
	@echo "project files removed from pox directory!"
	# Remove files from ext dir in pox
	rm -f $(poxdir)ext/baseController.py $(poxdir)ext/click_wrapper.py $(poxdir)ext/*.click
	# Kill controller
	@# use the regexp trick to not match grep itself. And ignore the error if no pox running
	-@ps -ef | grep '[p]ox.py' | awk '{print $$2}' | xargs -r sudo kill -9 2>/dev/null || true
	# Clean mininet
	sudo mn -c
	# Kill click processes
	-@sudo killall -SIGTERM click 2>/dev/null || true



