// Implementation of the CHNetworkPlainQueue class for word handling

#include "CHNetworkPlainQueue.h"

//#define UNIT_TEST 1


void RunIoService(boost::asio::io_service* io_service_param) {
    for (;;) {
    try
    {
      io_service_param->run();
      break; // run() exited normally
    }
    catch (boost::system::system_error& e)
    {
        printf("\n\nGOT EXCEPTION IN RunIoService!!!\n");
        printf("Exception data: %s\n", e.what());
        io_service_param->reset();
        
      // Deal with exception as appropriate.
    }
  }
}


CHNetworkPlainQueue::CHNetworkPlainQueue (uint16_t networkPort) {
    
    printf("CHNetworkPlainQueue::CHNetworkPlainQueue(%d)\n", networkPort);
    this->portNumber = networkPort;
    
    // Init various variables to zero/null
    this->numberPlainsProcessed = 0;
    this->NetworkServer = NULL;
}

uint64_t CHNetworkPlainQueue::getNumberPlainsInQueue() {
    return this->plainQueue.size();
}

uint64_t CHNetworkPlainQueue::getNumberPlainsProcessed() {
    return this->numberPlainsProcessed;
}


void CHNetworkPlainQueue::addPlainsToQueue(std::vector<std::string> plainsToAdd) {
    uint32_t i;
        
    this->queueMutex.lock();
    
    for (i = 0; i < plainsToAdd.size(); i++) {
        this->plainQueue.push(plainsToAdd[i]);
    }
    this->queueMutex.unlock();
}

std::vector <std::string> CHNetworkPlainQueue::getNextNPlains(uint32_t plainsToGet) {
    
}


void CHNetworkPlainQueue::startNetwork() {
    printf("CHNetworkPlainQueue::startNetwork()\n");
    
    int i;

    // Only create the network server if it's not already present.
    if (!this->NetworkServer) {
        this->NetworkServer = new CHNetworkPlainQueueInstance(this->io_service, this->portNumber, this);
    }
    
    // Launch all the network IO threads
    for (i = 0; i < MAX_IO_THREADS; i++) {
        this->ioThreads[i] = new boost::thread(RunIoService, &this->io_service);
    }
}


// Stop the io_service instances, and wait for all the threads to return.
void CHNetworkPlainQueue::stopNetwork() {

    int i;

    this->io_service.stop();
    for (i = 0; i < MAX_IO_THREADS; i++) {
        this->ioThreads[i]->join();
    }
}




// CHNetworkServerSession functions
void CHNetworkPlainQueueSession::start() {
    printf("In CHNetworkPlainQueueSession::start()\n");

    sprintf(this->hostIpAddress, "%s", socket_.remote_endpoint().address().to_string().c_str());

    socket_.async_read_some(boost::asio::buffer(data_, max_length),
            boost::bind(&CHNetworkPlainQueueSession::handle_read, this,
            boost::asio::placeholders::error,
            boost::asio::placeholders::bytes_transferred));
}



void CHNetworkPlainQueueSession::handle_read(const boost::system::error_code& error,
            size_t bytes_transferred) {
        //printf("In session::handle_read()\n");
        //printf("Buffer (%d): %c\n", bytes_transferred, data_[0]);
        
        if (!error) {
            if (bytes_transferred > 0) {
                // Do stuff
                uint32_t i;
                
                for (i = 0; i < bytes_transferred; i++) {
                    this->charBuffer.push_back(data_[i]);
                }
            }
            if (this->charBuffer.size() > 100000) {
                this->addWordsToQueue();
            }

            socket_.async_read_some(boost::asio::buffer(data_, max_length),
                boost::bind(&CHNetworkPlainQueueSession::handle_read, this,
                boost::asio::placeholders::error,
                boost::asio::placeholders::bytes_transferred));

        } else {
            // Report the disconnect
            printf("\n\nDSC: %s", this->hostIpAddress);
            this->addWordsToQueue();
            delete this;
        }


    }


// This is the slow function.  Optimize here!
void CHNetworkPlainQueueSession::addWordsToQueue() {
    std::string wordToAdd;
    int nextNewline = -1, i = 0;

    // We queue all these up so we only add once per packet.
    std::vector<std::string> plainsToAdd;
    
    plainsToAdd.reserve(this->charBuffer.size() / 6);
        
    // Loop until we return.
    while (1) {
        // Find the next newline character in the queue.
        nextNewline = -1;
        for (i = 0; i < this->charBuffer.size(); i++) {
            if ((this->charBuffer[i] == '\n') || (this->charBuffer[i] == '\r')) {
                nextNewline = i;
                break;
            }
        }

        //printf("Found next newline at pos %d\n", nextNewline);

        // If the newline is not found, we're out of words.  Return.
        if (nextNewline == -1) {
            this->networkPlainQueue->addPlainsToQueue(plainsToAdd);
            //printf("returning with charbuffer size %d\n", this->charBuffer.size());
            return;
        }


        // Otherwise, we've found a word!
        wordToAdd.clear();
        for (i = 0; i < nextNewline; i++) {
            wordToAdd += this->charBuffer.front();
            this->charBuffer.pop_front();
        }

        // Done?

        //printf("Word: %s\n", wordToAdd.c_str());
        plainsToAdd.push_back(wordToAdd);

        // Now remove any newlines before we try the next round.
        while (this->charBuffer.size() && ((this->charBuffer.front() == '\n') || (this->charBuffer.front() == '\r'))) {
            this->charBuffer.pop_front();
        }
    }
}
/*
void CHNetworkServerSession::handle_write(const boost::system::error_code& error) {
        //printf("In session::handle_write()\n");
        //printf("Current action: %d\n", this->currentAction);

        if (this->currentAction == NETWORK_ACTION_HASHLIST) {
            // If the action was a hash list, delete the send buffer.
            delete[] this->hashList;
        } else if (this->currentAction == NETWORK_ACTION_CHARSET) {
            delete[] this->charset;
        }
        this->currentAction = 0;

        
        if (!error) {
            socket_.async_read_some(boost::asio::buffer(data_, max_length),
                    boost::bind(&CHNetworkServerSession::handle_read, this,
                    boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred));
        } else {
            delete this;
        }
    }
*/



#if UNIT_TEST

#include <unistd.h>

int main() {
    
    CHNetworkPlainQueue NetworkQueue(4444);
    
    NetworkQueue.startNetwork();
    
    while (1) {
        sleep(1);
        printf("Size of buffer: %d\n", NetworkQueue.getNumberPlainsInQueue());
    }
    
}

#endif