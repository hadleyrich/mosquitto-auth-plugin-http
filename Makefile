NAME      = mosquitto_auth_plugin_http

MOSQUITTO = $(HOME)/mosquitto-1.3.5
INC       = -I. -I$(MOSQUITTO)/lib -I$(MOSQUITTO)/src
CFLAGS    = -Wall -Werror -fPIC
#DEBUG     = -DMQAP_DEBUG

LIBS      = -lcurl

all: $(NAME).so

$(NAME).so: $(NAME).o
	$(CC) $(CFLAGS) $(INC) -shared $^ -o $@ $(LIBS)

%.o : %.c
	$(CC) -c $(CFLAGS) $(DEBUG) $(INC) $< -o $@

clean:
	rm -f *.o *.so

