#include "io_helper.h"
#include "request.h"
//#include <sys/syscall.h>

#define MAXBUF (8192)


// Structure for request
typedef struct Request_Tag
{
    int fd;
    char *name;
    int size;
    struct Request_Tag* next;
} Request;

// Structure for Queue
typedef struct Queue_Tag
{
    Request* front;
    Request* rear;
} Queue;

// Initializing queue
void Init(Queue* qptr)
{
    qptr->front = NULL;
    qptr->rear = NULL;
}

// Insertion into queue
Queue* Insert(Queue* qptr, int fd, char *name, int size, int scheduling)
{

    // Create a new node.
    Request* nptr = (Request*) malloc(sizeof(Request));

    // Assign appropriate values to the node.
    nptr->fd = fd;
    nptr->name = (char*) malloc(sizeof(char) * 20);
    strcpy(nptr->name, name);
    nptr->size = size;
        
    nptr->next = NULL;
        
    if(qptr->front == NULL && qptr->rear == NULL)
    {
        qptr->front = qptr->rear = nptr;
    }
    else
    {
        // According to the scheduling policy, insert the node in the appropriate location
        if (scheduling == 0)
        {
            // At the end for FIFO
            (qptr->rear)->next = nptr;
            qptr->rear = nptr;
        }
        else
        {
            // Go through the list and insert it in ascending order of file size for SFF.
            Request* prev = NULL, * ptr = qptr->front;
            while (ptr != NULL && ptr->size < nptr->size)
            {
                prev = ptr;
                ptr = ptr->next;
            }

            if (prev == NULL)
            {
                nptr->next = qptr->front;
                qptr->front = nptr;
            }
            else
            {
                nptr->next = ptr;
                prev->next = nptr;
            }
        }
    }
    return qptr;
}


// Delete from the front of the queue
Queue* Delete(Queue* qptr)
{
    Request* nptr;

    if(qptr->front != NULL || qptr->rear != NULL)
    {
        nptr = qptr->front;

        qptr->front = (qptr->front)->next;

        if(qptr->front == NULL)
        {
            qptr->rear = NULL;
        }
        free(nptr);
    }
    return qptr;
}

Queue* buffer = NULL;

pthread_cond_t empty = PTHREAD_COND_INITIALIZER, fill = PTHREAD_COND_INITIALIZER;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

//
// Sends out HTTP response in case of errors
//
void request_error(int fd, char *cause, char *errnum, char *shortmsg, char *longmsg) {
    char buf[MAXBUF], body[MAXBUF];
    
    // Create the body of error message first (have to know its length for header)
    sprintf(body, ""
	    "<!doctype html>\r\n"
	    "<head>\r\n"
	    "  <title>OSTEP WebServer Error</title>\r\n"
	    "</head>\r\n"
	    "<body>\r\n"
	    "  <h2>%s: %s</h2>\r\n" 
	    "  <p>%s: %s</p>\r\n"
	    "</body>\r\n"
	    "</html>\r\n", errnum, shortmsg, longmsg, cause);
    
    // Write out the header information for this response
    sprintf(buf, "HTTP/1.0 %s %s\r\n", errnum, shortmsg);
    write_or_die(fd, buf, strlen(buf));
    
    sprintf(buf, "Content-Type: text/html\r\n");
    write_or_die(fd, buf, strlen(buf));
    
    sprintf(buf, "Content-Length: %lu\r\n\r\n", strlen(body));
    write_or_die(fd, buf, strlen(buf));
    
    // Write out the body last
    write_or_die(fd, body, strlen(body));
    
    // close the socket connection
    close_or_die(fd);
}

//
// Reads and discards everything up to an empty text line
//
void request_read_headers(int fd) {
    char buf[MAXBUF];
    
    readline_or_die(fd, buf, MAXBUF);
    while (strcmp(buf, "\r\n")) {
		readline_or_die(fd, buf, MAXBUF);
    }
    return;
}

//
// Return 1 if static, 0 if dynamic content (executable file)
// Calculates filename (and cgiargs, for dynamic) from uri
//
int request_parse_uri(char *uri, char *filename, char *cgiargs) {
    char *ptr;
    
    if (!strstr(uri, "cgi")) { 
	// static
	strcpy(cgiargs, "");
	sprintf(filename, ".%s", uri);
	if (uri[strlen(uri)-1] == '/') {
	    strcat(filename, "index.html");
	}
	return 1;
    } else { 
	// dynamic
	ptr = index(uri, '?');
	if (ptr) {
	    strcpy(cgiargs, ptr+1);
	    *ptr = '\0';
	} else {
	    strcpy(cgiargs, "");
	}
	sprintf(filename, ".%s", uri);
	return 0;
    }
}

//
// Fills in the filetype given the filename
//
void request_get_filetype(char *filename, char *filetype) {
    if (strstr(filename, ".html")) 
		strcpy(filetype, "text/html");
    else if (strstr(filename, ".gif")) 
		strcpy(filetype, "image/gif");
    else if (strstr(filename, ".jpg")) 
		strcpy(filetype, "image/jpeg");
    else 
		strcpy(filetype, "text/plain");
}

//
// Handles requests for static content
//
void request_serve_static(int fd, char *filename, int filesize) {
    int srcfd;
    char *srcp, filetype[MAXBUF], buf[MAXBUF];
    
    request_get_filetype(filename, filetype);
    srcfd = open_or_die(filename, O_RDONLY, 0);
    
    // Rather than call read() to read the file into memory, 
    // which would require that we allocate a buffer, we memory-map the file
    srcp = mmap_or_die(0, filesize, PROT_READ, MAP_PRIVATE, srcfd, 0);
    close_or_die(srcfd);
    
    // put together response

    
    
    sprintf(buf, ""
	    "HTTP/1.0 200 OK\r\n"
	    "Server: OSTEP WebServer\r\n"
	    "Content-Length: %d\r\n"
	    "Content-Type: %s\r\n\r\n", 
	    filesize, filetype);
     
    write_or_die(fd, buf, strlen(buf));
    
    //  Writes out to the client socket the memory-mapped file 
    write_or_die(fd, srcp, filesize);
    munmap_or_die(srcp, filesize);
}

//
// Fetches the requests from the buffer and handles them (thread logic)
//
void* thread_request_serve_static(void* arg)
{

    while (1)
    {
        sleep(1);

        // Allocate memory for a request
        Request* req = (Request*) malloc(sizeof(Request));

        // Acquire lock
        pthread_mutex_lock(&mutex);

        // Wait if buffer is empty.
        while(buffer_size == 0)
        {
             pthread_cond_wait(&fill, &mutex);
        }

        // Assign values to the request node
        req->fd = buffer->front->fd;
        req->size = buffer->front->size;
        req->name = (char*) malloc(sizeof(char) * 20);
        strcpy(req->name, buffer->front->name);
        
        // Delete from front of the buffer.
        buffer_size--;
        buffer = Delete(buffer);
        
        //printf("%s removed. buffersize: %d thread %d\n", req->filename, buffer_size, syscall(__NR_gettid));
        printf("Request for %s is removed from the buffer\n", req->name, buffer_size);
        pthread_cond_signal(&empty);

        // Release lock
        pthread_mutex_unlock(&mutex);

        // Handle the request.
        request_serve_static(req->fd, req->name, req->size);
        close_or_die(req->fd);

        free(req);
    }
}

//
// Initial handling of the request
//
void request_handle(int fd) {
    int is_static;
    struct stat sbuf;
    char buf[MAXBUF], method[MAXBUF], uri[MAXBUF], version[MAXBUF];
    char filename[MAXBUF], cgiargs[MAXBUF];
    
	// get the request type, file path and HTTP version
    readline_or_die(fd, buf, MAXBUF);
    sscanf(buf, "%s %s %s", method, uri, version);
    printf("method:%s uri:%s version:%s\n", method, uri, version);

	// verify if the request type is GET or not
    if (strcasecmp(method, "GET")) {
		request_error(fd, method, "501", "Not Implemented", "server does not implement this method");
		return;
    }
    request_read_headers(fd);
    
	// check requested content type (static/dynamic)
    is_static = request_parse_uri(uri, filename, cgiargs);

    if (strstr(filename, ".."))
    {
        request_error(fd, filename, "403", "Forbidden", "Traversing up in filesystem is not allowed");
		return;
    }
    
	// get some data regarding the requested file, also check if requested file is present on server
    if (stat(filename, &sbuf) < 0) {
		request_error(fd, filename, "404", "Not found", "server could not find this file");
		return;
    }
    
	// verify if requested content is static
    if (is_static) {
		if (!(S_ISREG(sbuf.st_mode)) || !(S_IRUSR & sbuf.st_mode)) {
			request_error(fd, filename, "403", "Forbidden", "server could not read this file");
			return;
		}
		

        // Acquire lock
        pthread_mutex_lock(&mutex);

        if (buffer == NULL)
        {
            buffer = (Queue*) malloc(sizeof(Queue));
            Init(buffer);
        }

        // Wait if buffer is full
        while(buffer_size >= buffer_max_size)
        {
            pthread_cond_wait(&empty, &mutex);
        }

        // Insert into buffer according to scheduling policy
        buffer = Insert(buffer, fd, filename, sbuf.st_size, scheduling_algo);
        buffer_size++;
        printf("Request for %s is added to the buffer\n", filename);
        
        pthread_cond_signal(&fill);

        // Release lock
        pthread_mutex_unlock(&mutex);
        
        
    } else {
		request_error(fd, filename, "501", "Not Implemented", "server does not serve dynamic content request");
    }
    
}
