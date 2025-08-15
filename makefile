# Define the source file and destination
SOURCE = chatbot.py
DESTINATION = /usr/local/bin/chatbot

# Default target
all: install

# Install the chatbot script
install:
	@echo "Installing $(SOURCE) to $(DESTINATION)..."
	# ln -s $(SOURCE) $(DESTINATION)
	sudo ln -s $(shell pwd)/$(SOURCE) $(DESTINATION)
	chmod +x $(DESTINATION)

# Uninstall the chatbot script
uninstall:
	@echo "Uninstalling $(DESTINATION)..."
	sudo rm $(DESTINATION)

