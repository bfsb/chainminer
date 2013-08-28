#ifndef HANDYLIBHTTP_H
#define HANDYLIBHTTP_H

#ifndef HANDYLIBTHREAD_H
#define HANDYLIBTHREAD_H

#include <iostream>
#include <setjmp.h>
#include <errno.h>

#ifndef NO_PTHREADS
#include <pthread.h>
#include <sys/time.h>
#else
#include <map>
#endif

namespace handylib {

enum {
/// Wait for exception. @see Thread::WaitOnFD
WAIT_EX = 1,
/// Wait for opened file to accept writing. @see Thread::WaitOnFD
WAIT_WRITE = 2,
/// Wait for opened file to have data for reading. @see Thread::WaitOnFD
WAIT_READ = 4
};

/// Class that allows you to launch process, and redirects streams
/// to stdin and stdout, also error stream is initialized.
class PRunBuf;
class PRun : public std::iostream
{
	public:
	PRun(const char *filename, char *const av[], char *const env[], int to = 5000);
	PRun(const char *filename, char *const av[], int to = 5000);
	void closeInput();
	~PRun();
	private:
	PRunBuf *p;
	public:
	std::istream err;
};

/** @class Timer 
    @brief Used to perform timing with precision to milliseconds.

    Typically this class is used to count down timeouts and/or to watch
    intervals between events. The timer may be active or inactive. All
    parameters are measured in milliseconds. Due to OS limitations timer
    may not be so precise.
*/
class Timer
{
	unsigned timer;
	bool active;
	public:
	/// Constructs inactive timer.
	Timer() { active = false; timer = getCurrent(); }
	
	const static unsigned infinite = ~(unsigned)0; /**< infinite value of time interval */

	const static unsigned inf = ~(unsigned)0; /**< infinite value of time interval */

	/**
	 @brief Resets timer and prepares to countdown.
	 @param timeout Time interval to countdown. If 0 ms, then timer will be reset and its state will be inactive.
	*/
	void setTimer(unsigned timeout = 0) {
		active = false;
		timer = getCurrent();
		if (timeout) incTimer(timeout);
	}

	/// Increments countdown timeout, activates timer.
	void incTimer(unsigned timeout) { timer += timeout >> 4; active = true; }
	/// Decrements countdown timeout, activates timer.
	void decTimer(unsigned timeout) { timer -= timeout >> 4; active = true; }
	void endTimer(void) { active = false; } /**< Deactivates timer. */
	/** @brief Get time left.
	    @return If timer is inactive, then infinite will be returned. If timeout was elapsed, then 0 will be returned. Otherwise milliseconds left to timeout expiration are returned.
	 */
	unsigned getTimer(unsigned cur = Timer::inf) const {
		if (!active) return inf;
		if (cur == Timer::inf) cur = getCurrent();
		if (cur < timer) return (timer - cur) << 4;
		return 0;
	}
	/** @brief Get time elapsed.
	    @return Get time elapsed after timeout was hit. If timer is inactive, then infinite will be returned. If timeout was not hit, then 0 will be returned. Otherwise milliseconds elapsed after timeout was hit are returned.
	 */
	unsigned getElapsed(unsigned cur = Timer::inf) const {
		if (!active) return inf;
		if (cur == Timer::inf) cur = getCurrent();
		if (cur > timer) return (cur - timer) << 4;
		return 0;
	}
		
	/// Returns current time in milliseconds / 16
	unsigned getCurrent(void) const;
};

/// Yield execution to threads. Returns 0 when no threads are waiting or milliseconds needed to wake next thread.
unsigned threads_yield();

/// Launch sleep call, that will not stop other threads.
void threads_sleep(unsigned ms);

/// Give control to threads. While at least one thread exists, this function will not exit. Threads will be looped and contexts will be switched.
void threads_mainloop();

/// I/O multiplexing with threads. @see Thread::WaitOnFD
bool threads_waitonfd(int fd, int wait, unsigned timeout);

class Thread;

/// Get current thread. (Thread*)0 is returned if getThread() is called from outside thread dispatcher scope.
Thread *getThread();

/// Soft Thread object. In this thread implementation switching is done not by operating system, but in userspace program. It is very useful in some cases.
class Thread
{
	jmp_buf f_run;
	Thread *f_next, *f_prev;
	char *stack;
	int f_stacksize;
	enum state { THREAD_INITIAL = 0, THREAD_RUNNING, THREAD_TERMINATE };
	
	Timer f_sleep;
	state f_state;
	bool f_cancel;

	public:
	typedef void (*onexit_callback_t)(Thread *th);
	private:
	onexit_callback_t onexit; /* Function that will be called when this thread would exit */
	public:
#ifndef NO_PTHREADS
	class mutex {
		pthread_mutex_t m;
		public:
		//mutex() { pthread_mutex_init(&m,0); }
		mutex() { pthread_mutex_init(&m,NULL); }
		~mutex() { trylock(); unlock(); pthread_mutex_destroy(&m); }
		void lock() { pthread_mutex_lock(&m); }
		void unlock() { pthread_mutex_unlock(&m); }
		bool trylock() { if (pthread_mutex_trylock(&m) < 0) return false; return true; }
	};
	class event {
		pthread_cond_t c;
		pthread_mutex_t m;
		public:
		event() { pthread_cond_init(&c,0); pthread_mutex_init(&m,0); }
		~event() { pthread_cond_broadcast(&c); pthread_cond_destroy(&c); pthread_mutex_trylock(&m); pthread_mutex_unlock(&m); pthread_mutex_destroy(&m); }

		void signalOne() { pthread_mutex_lock(&m);pthread_cond_signal(&c);pthread_mutex_unlock(&m);}
		void signal() { pthread_mutex_lock(&m);pthread_cond_broadcast(&c);pthread_mutex_unlock(&m);}

		void wait() { pthread_mutex_lock(&m); pthread_cond_wait(&c,&m); pthread_mutex_unlock(&m); }
		bool wait(unsigned timeout) { pthread_mutex_lock(&m); struct timespec ts; { struct timeval tv; gettimeofday(&tv,0); ts.tv_sec = tv.tv_sec + (timeout/1000); ts.tv_nsec = 1000*(tv.tv_usec+(timeout%1000)); } int r; for (;;) { r = pthread_cond_timedwait(&c,&m,&ts); if (r != EINTR) break; } pthread_mutex_unlock(&m); if (r == ETIMEDOUT) return false; return true; }
	};
	class rwlock {
		pthread_rwlock_t lock;
		public:
		rwlock() { pthread_rwlock_init(&lock,0); }
		~rwlock() { pthread_rwlock_destroy(&lock); }
		
		void readlock() { pthread_rwlock_rdlock(&lock); }
		void writelock() { pthread_rwlock_wrlock(&lock); }
		void unlock() { pthread_rwlock_unlock(&lock); }
	};
#else
	class event {
		std::map<Thread*, bool> th;
		public:
		void signal() { for (std::map<Thread*,bool>::iterator i = th.begin(); i != th.end(); ++i) i->first->unsleep(); th.clear(); }
		void signalOne() { if (th.begin() == th.end()) return; th.begin()->first->unsleep(); th.erase(th.begin()); }
		void wait() { Thread *t = getThread(); if (!t) return; th[t] = true; while (!t->testCancel()) { if (th.find(t) == th.end()) return; t->Sleep(100000); } if (th.find(t) != th.end()) th.erase(th.find(t)); }
		bool wait(unsigned timeout) { Thread *t = getThread(); if (!t) return false; th[t] = true; t->Sleep(timeout); std::map<Thread*,bool>::iterator i = th.find(t); if (i == th.end()) return true; th.erase(i); return false; }
	};
	class mutex {
		int n;
		public:
		mutex() : n(0) { }
		~mutex() { }
		void lock() { while (n) threads_sleep(100); n = 1; }
		void unlock() { n = 0; }
		bool trylock() { if (n) return false; n = 1; return true; }
	};
	class rwlock {
		int nr, nw;
		public:
		rwlock() { nr = nw = 0; }
		~rwlock() { }
		void readlock() { while (nw > 0) threads_sleep(100); ++nr; }
		void writelock() { while (nr > 0 || nw > 0) threads_sleep(100); nr = 0; nw = 1; }
		void unlock() { if (nw > 0) { nw = 0; nr = 0; } if (nr > 0) --nr; }
	};
#endif
	class mlock {
		mutex& m;
		public:
		mlock(mutex& m1) : m(m1) { m.lock(); }
		~mlock() { m.unlock(); }
		operator mutex& () { return m; }
	};

	class readlock {
		rwlock& l;
		public:
		readlock(rwlock& l1) : l(l1) { l.readlock(); }
		~readlock() { l.unlock(); }
		operator rwlock& () { return l; }
	};

	class writelock {
		rwlock& l;
		public:
		writelock(rwlock& l1) : l(l1) { l.writelock(); }
		~writelock() { l.unlock(); }
		operator rwlock& () { return l; }
	};

	/// Construct new thread.
	Thread(int stacksize = 64000);
	/// Construct new thread as a copy of some thread.
	Thread(const Thread& fib);

	/// Callbacks
	void onExit(onexit_callback_t func) { if (!onexit) onexit = func; }

	/// Destroy thread.
	virtual ~Thread();

	/// Terminate thread.
	void Terminate();

	/// Automatically delete thread when terminated.
	void setAutoDelete() { f_autodelete = true; }
	
	/// When thread was constructed, it will be put to INITIAL STATE. Use this method to actually run thread.
	void Start();
	
	/// Suspend thread execution.
	void Suspend();

	/// Resume thread execution.
	void Resume();
	
	/// Sleep thread for some time.
	void Sleep(unsigned msec);

	/// Cancel thread.
	void Cancel() { f_cancel = true; wakeThread(); }

	/// Returns true if thread is running.
	bool isRunning() { return f_state == Thread::THREAD_INITIAL || f_state == Thread::THREAD_RUNNING; }

	/// Returns true if thread was constructed but never run.
	bool isInitial() { return f_state == Thread::THREAD_INITIAL; }

	/// Returns true if thread was cancelled.
	bool testCancel() { return f_cancel; }

	/// Unsleep thread.
	void unsleep() { f_sleep.endTimer(); }

	/// Optional thread initializer
	void doInit();

	/// Awake thread
	void wakeThread();

	bool f_autodelete; // automatically delete thread in loop

	protected:
	
	/// I/O multiplexing using threads. Returns false if timeout was hit.
	bool WaitOnFD(int fd, int wait, unsigned timeout);

	/// Yield execution to other threads.
	void Yield();

	/// Synonym for Terminate(). @see Terminate()
	void Exit() { Terminate(); }
	
	/// This method is called when thread is initiated.
	virtual void Initial();

	/// This method is called when thread is finalized.
	virtual void Final();

	/// This method is called to start thread.
	virtual void Run() = 0;

	friend unsigned threads_yield();
	friend bool threads_waitonfd(int fd, int wait, unsigned timeout);
};

};

#endif

#ifndef HANDYLIBDATETIME_H
#define HANDYLIBDATETIME_H

#include <string>

namespace handylib {

extern int Time_dummy_int;

/// Work with two time representation - seconds and human-readable date/time.
class Time
{
	mutable unsigned secs;
	struct Cache {
		int sec, min, hour, mday, mon, year, wday, yday;
		char tzname[8];
	};
	mutable Cache *cache;
	int tzi;

	void lcache() const;
	void scache() const;
	void ucache() const;
	public:
	/// Initialize zero Time object.
	Time() { cache = (Cache*)0; secs = 0; tzi = gettz(); }
	/// Initialize Time object from seconds.
	Time(unsigned s) { cache = (Cache*)0; secs = s; tzi = gettz(); if (s == 0xffffffff) *this = now(); }
	/// Initialize Time object from other time object.
	Time(const Time& dt) { cache = (Cache*)0; tzi = dt.tz(); secs = dt.seconds(); }
	/// Construct datetime object from a YYYYMMDDHHMMSS timestamp.
	Time(const char *ts);
	/// Construct time using parse format and string.
	Time(const char *pf, const char *tm, bool gmt = false) { cache = (Cache*)0; if (!gmt) tzi = gettz(); else tzi = 0; secs = 0; parse(pf,tm); }
	/// Construct a copy of Time object.
	~Time() { if (cache) ucache(); }

	/// Copy datetime object.
	Time& operator = (const Time& dt) { if (cache) ucache(); secs=dt.seconds(); return *this; }

	/// Returns SQL timestamp YYYYMMDDHHMMSS shortened to len.
	std::string timestamp(int len = 14) const;

	/** Format string output. fmt is a format string.
	
	 @return formatted date.
	 
	 %% - a % character.
	 %a - abbreviated weekday name (Sun..Sat)
	 %A - full weekday name (Sunday..Saturday)
	 %b - abbreviated month name (Jan..Dec)
	 %B - full month name (January..December)
	 %d - day of month (01..31)
	 %e - day of month blank padded ( 1..31)
	 %H - hour (00..23)
	 %I - hour (01..12)
	 %j - day of year (001..366)
	 %k - hour ( 0..23)
	 %l - hour ( 1..23)
	 %m - month (01..12)
	 %M - minute (00..59)
	 %p - AM or PM
	 %s - seconds since 00:00:00, Jan 1, 1970
	 %S - second (00..60)
	 %t - time zone name (GMT, UTC, ...) if unknown then %T will be used.
	 %T - UTC time zone (-0215, 0000, +0324, ...)
	 %u - UTC time zone hours (-0200, 0000, +0300, ...)
	 %U - UTC time zone (-02, 00, +03, ...)
	 %w - day of week (0..6) 0 = Sunday
	 %y - last two digits of year
	 %Y - year (1970...)
	*/
	std::string format(const char *fmt) const;

	/** Parse formatted string.
	
	  @param fmt Format. @see format
	  @param str String to parse.

	  space matches any whitespace. other characters MUST match exactly.
	 
	 %% - a % character.
	 %a - skip weekday abbr (Sun..Sat)
	 %A - skip weekday name (Sunday..Saturday)
	 %j - skip integer
	 %b - abbreviated month name (Jan..Dec)
	 %B - full month name (January..December)
	 %d - day of month (1..31)
	 %H - hour (00..23)
	 %I - hour (01..12)
	 %m - month (1..12)
	 %M - minute (0..59)
	 %p - AM or PM
	 %s - seconds since 00:00:00, Jan 1, 1970
	 %S - second (0..60)
	 %T - UTC time zone (-0215, 0000, +0324, ...)
	 %u - UTC time zone hours (-0200, 0000, +0300, ...)
	 %U - UTC time zone (-02, 00, +03, ...)
	 %y - last two digits of year
	 %Y - year (1970...)
	*/
	void parse(const char *fmt, const char *str);

	/// Parse HTTP date in all possible formats.
	void parseHTTP(const char *str);

	/// Format HTTP date.
	std::string formatHTTP();

	/// Set current time.
	Time& now();

	/// Get seconds.
	int sec() const { if (!cache) lcache(); if (!cache) return 0; return cache->sec; }
	/// Get minutes.
	int min() const { if (!cache) lcache(); if (!cache) return 0; return cache->min; }
	/// Get hours.
	int hour() const { if (!cache) lcache(); if (!cache) return 0; return cache->hour; }
	/// Get day of month.
	int mday() const { if (!cache) lcache(); if (!cache) return 0; return cache->mday; }
	/// Get month (0..11).
	int mon() const { if (!cache) lcache(); if (!cache) return 0; return cache->mon; }
	/// Get year.
	int year() const { if (!cache) lcache(); if (!cache) return 0; return cache->year; }
	/// Get week day.
	int wday() const { if (!cache) lcache(); if (!cache) return 0; return cache->wday; }
	/// Get year day.
	int yday() const { if (!cache) lcache(); if (!cache) return 0; return cache->yday; }
	/// Get difference with UTC.
	int tz() const { return tzi; }
	/// Get timezone name (may be in format -00xx)
	const char *tzname() const;
	
	/// Modify seconds.
	int& xsec() { if (!cache) lcache(); if (!cache) return Time_dummy_int; secs = ~0u; return cache->sec; }
	/// Modify minutes.
	int& xmin() { if (!cache) lcache(); if (!cache) return Time_dummy_int; secs = ~0u; return cache->min; }
	/// Modify hours.
	int& xhour() { if (!cache) lcache(); if (!cache) return Time_dummy_int; secs = ~0u; return cache->hour; }
	/// Modify day of month.
	int& xmday() { if (!cache) lcache(); if (!cache) return Time_dummy_int; secs = ~0u; return cache->mday; }
	/// Modify month (0u..11).
	int& xmon() { if (!cache) lcache(); if (!cache) return Time_dummy_int; secs = ~0u; return cache->mon; }
	/// Modify year.
	int& xyear() { if (!cache) lcache(); if (!cache) return Time_dummy_int; secs = ~0u; return cache->year; }
	/// Modify week day.
	int& xwday() { if (!cache) lcache(); if (!cache) return Time_dummy_int; secs = ~0u; return cache->wday; }
	/// Modify year day.
	int& xday() { if (!cache) lcache(); if (!cache) return Time_dummy_int; secs = ~0u; return cache->yday; }
	/// Modify difference with UTC. Really time in seconds since Epoch will not change.
	int& xtz() { if (cache) { if (secs == ~0u) scache(); ucache(); } return tzi; }
	/// Move difference with UTC. Time in seconds since Epoch will change.
	int& xmtz() { if (!cache) lcache(); if (!cache) return Time_dummy_int; cache->tzname[0] = 0; secs = ~0u; return tzi; }

	/// Normalize modified values.
	void normalize() { if (cache) { scache(); lcache(); } }

	/// Set to 1970 January 1 00:00:00
	void zero() { xmday() = 1; xmon() = xhour() = xmin() = xsec() = 0; xyear() = 70; }

	/// Set to 0 seconds.
	void erase() { if (cache) ucache(); secs = 0; }

	/// Get seconds.
	unsigned seconds () const { if (cache && secs == ~0u) scache(); return secs; }

	/// Modify seconds.
	unsigned& xseconds () { if (cache) { if (secs == ~0u) scache(); ucache(); } return secs; }

	/// Add some seconds.
	Time& operator += (unsigned s) { xseconds() += s; return *this; }
	/// Substract some seconds.
	Time& operator -= (unsigned s) { xseconds() -= s; return *this; }
	/// Substract two Time objects.
	int operator - (const Time& t) const { return (int)seconds() - (int)t.seconds(); }

	/// Compare time.
	bool operator < (const Time& t) const { return seconds() < t.seconds(); }
	/// Compare time.
	bool operator > (const Time& t) const { return seconds() > t.seconds(); }
	/// Compare time.
	bool operator <= (const Time& t) const { return seconds() <= t.seconds(); }
	/// Compare time.
	bool operator >= (const Time& t) const { return seconds() >= t.seconds(); }
	/// Compare time.
	bool operator == (const Time& t) const { return seconds() == t.seconds(); }
	/// Compare time.
	bool operator != (const Time& t) const { return seconds() != t.seconds(); }

	/// Get the difference between Coordinated Universal Time (UTC) and local standard time in seconds.
	static int gettz();

	/// Set the difference between Coordinated Universal Time (UTC) and local standard time in seconds.
	static void settz(int tz);

	/// Get local timezone name.
	static const char *gettzname();

	/// Set local timezone name.
	static void settzname(const char *s);

	/// Get Enclosing Week
	void getEnclosingWeek(Time& start, Time& end);
};

};

#endif

#ifndef HANDYLIBSOCKET_H
#define HANDYLIBSOCKET_H

#include <string>
#include <iostream>

namespace handylib {

/// Interface class to use common addresses in socket functions.
class SocketAddress
{
	public:
	SocketAddress() { } ///< Empty constructor.
	virtual ~SocketAddress(); ///< User-provided destructor.
	/// Set address using its binary representation.
	virtual void setAddress(const void *addr, int addr_len) = 0;
	/// Get address using its binary representation.
	virtual int getAddress(void *addr, int addr_maxlen) const = 0;
};

/// Unix domain sockets address.
class UnixAddress : public SocketAddress
{
	std::string path;
	public:
	UnixAddress() : path() { } ///< No address default constructor.
	UnixAddress(const std::string& p) { path = p; } ///< UNIX address with path.
	virtual ~UnixAddress(); ///< Destructor.

	void setPath(const std::string& s) { path = s; } ///< Set UNIX address.
	std::string getPath() const { return path; } ///< Get UNIX address.
	
	virtual void setAddress(const void *addr, int addr_len);
	virtual int getAddress(void *addr, int addr_maxlen) const;
};

/// IPv4 address.
class IPAddress : public SocketAddress
{
	unsigned long ip;
	int port;
	public:
	/// Set ip address from std::string notation @see set
	IPAddress(const char *s) { set(s); }
	/// Set ip address from std::string notation.
	IPAddress(const std::string& h, const std::string& p) { set(h,p); }
	/// Set ip address from unsigned long and port number.
	IPAddress(unsigned long i, int p = 0) { ip = n2h(i); port = p; }
	/// Default address constructor.
	IPAddress() { ip = 0; port = 0; }
	virtual ~IPAddress();

	virtual void setAddress(const void *addr, int addr_len);
	virtual int getAddress(void *addr, int addr_maxlen) const;

	/// Get IP address as std::string. If needport is true, then port number will be added too.
	std::string getString(bool needport = false) const;

	/// Get IP address as std::string for reverse ptr lookup.
	std::string getRevString() const;

	/** Set ip address from std::string notation. If you supply "127.0.0.1:9991"
	    that will mean port 9991.
	*/
	bool set(const char *s);

	/// Set IP address directly from 32bit value and port number.
	void set(unsigned long i, int p = 0) { ip = n2h(i); if (p) port = p; }

	/// Set IP address from std::string notation.
	bool set(const std::string& s, const std::string& p);

	/// Set port number.
	void setPort(int p) { port = p; }

	/// Get port number.
	int getPort() const { return port; }

	/// Get 32bit IP address alone.
	unsigned long getIP() const { return h2n(ip); }
	
	/// Get 32bit IP address alone.
	operator unsigned long () const { return h2n(ip); }

	int getHIP() const { return (int)ip; }
	void setHIP(int x) { ip = (unsigned)x; }

	/// & operation for IP address and IP mask.
	IPAddress operator & (const IPAddress& a) const {return IPAddress(ip & a.ip); }
	
	/// &= operation for IP address and IP mask.
	IPAddress& operator &= (const IPAddress& a) { ip &= a.ip; return *this;}

	/// Compare two IP addresses.
	bool operator == (const IPAddress& a) const { return ip == a.ip; }
	
	/// Compare two IP addresses.
	bool operator < (const IPAddress& a) const { return ip < a.ip; }
	
	/// Compare two IP addresses.
	bool operator > (const IPAddress& a) const { return ip > a.ip; }
	
	/// Compare two IP addresses.
	bool operator <= (const IPAddress& a) const { return ip <= a.ip; }
	
	/// Compare two IP addresses.
	bool operator >= (const IPAddress& a) const { return ip >= a.ip; }
	
	/// Compare two IP addresses.
	bool operator != (const IPAddress& a) const { return ip != a.ip; }

	private:
	static unsigned long h2n(unsigned long x);
	static unsigned long n2h(unsigned long x);
};

/// Generic socket class.
class Socket
{
	protected:
	int so, flags;
	unsigned to;

	private:
	Socket(const Socket& s);
	Socket& operator =(const Socket& );

	public:
	/// Use with care
	int get_sock() { return so; }

	/// Description of error
	enum SocketError {
	OK = 0,
	FatalError, ///< Some fatal error happened, socket MUST NOT BE USED.
	ConnectionRefused, ///< Connection refused.
	NotConnected, ///< Socket is not connected.
	AlreadyConnected, ///< Socket was already connected.
	TimedOut, ///< Operation timed out.
	Unreachable, ///< Remote host is unreachable.
	AddressInUse, ///< Specified address is in use.
	NoSSL, ///< Compiled without SSL support.
	SSLFailure, ///< Bad certificate for accepting connection. Or unable to establish ssl connection.
	} err;
	/// Closes socket.
	virtual ~Socket();

	/// Use this method to shutdown socket immediately. 1 = Read shutdown. 2 = Write shutdown. 3 = Complete shutdown
	void shutdown(int dir = 3);

	/// Use this method to close socket immediately, when aborting connections.
	void close();

	/** If  this  option  is  enabled,  out-of-band data is directly placed
	    into the receive data stream. Otherwise out-of-band data is only
	    passed when the OOB flag is set during receiving. @see setOOB
	*/
	void setOOBInline(bool oobinline = true);

	/// Is out-of-band data inline option enabled ? @see setOOBInline
	bool getOOBInline();

	/**
        Indicates   that   the  rules  used  in  validating
        addresses supplied in a bind call  should  allow
        reuse  of local addresses. For PF_INET sockets this
        means that a socket may bind, except when there  is
        an  active  listening  socket bound to the address.
        When the listening socket is  bound  to  INADDR_ANY
        with  a  specific  port  then it is not possible to
        bind to this port for any local address.
	*/
	void setReuseAddr(bool reuse = true);

	/// Are we reusing addresses?
	bool getReuseAddr();

	/// Bind to specific device interface.
	void bindToDevice(const char *dev);

	/// Don't  send  via  a  gateway, only send to directly connected hosts.
	void setDontRoute(bool dontroute = true);

	/// Are we disabled routing of packets ?
	bool getDontRoute();

	/** When enabled, datagram sockets receive packets sent to a broadcast
	   address and they are allowed to send packets to a broadcast address.
	*/
	void setBroadcast(bool broadcast = true);

	/// Are broadcasts enabled? @see setBroadcast
	bool getBroadcast();

	/// Sets the maximum socket send buffer in bytes.
	void setSendBufferSize(int sndbuf = 4096);

	/// Gets the maximum socket send buffer in bytes.
	int getSendBufferSize();

	/// Sets the maximum socket receive buffer in bytes.
	void setRecvBufferSize(int rcvbuf = 4096);
	
	/// Gets the maximum socket receive buffer in bytes.
	int getRecvBufferSize();

	/// Enables/disables OOB flag for send/receive calls.
	void setOOB(bool oob = true);

	/// Gets OOB flag for send/receive calls.
	bool getOOB();

	/// Set socket timeout for miscellaneous operations in milliseconds.
	void setTimeout(unsigned t) { to = t; }

	/// Get current socket timeout.
	unsigned getTimeout() { return to; }
	
	/// Send packet to specified address.
	int sendto(const void *msg, unsigned len, const SocketAddress& to);

	/// Receive packet from specified address.
	int recvfrom(void *buf, unsigned len, SocketAddress& from);

	/// Bind socket to specified address.
	void bind(const SocketAddress& addr);

	/// Initialize zero linger
	void setZeroLinger();

	protected:
	Socket();
};

class StreamServerSocket;

/// Streamable connection-oriented sockets.
class StreamSocket : virtual public Socket, public std::streambuf, public std::iostream
{
	private:
		void setBroadcast(bool) { }
		bool getBroadcast() { return false; }
	
	public:
	virtual ~StreamSocket();

	/// Wait while data is not available for msec milliseconds. Returns true if
	/// data have arrived. False - if timeout elapsed.
	bool waitForData(unsigned msec);

	/// Enable  sending  of  keepalive messages on connection-oriented sockets.
	void setKeepAlive(bool keepalive = true);

	/// Is keepalive messages enabled?
	bool getKeepAlive();

	protected:

	char *gbuf, *pbuf;
	int bufsize;
	std::streampos gpos, ppos;

	void EmergeBuffers();
	void DropBuffers();
	
	void connect(const SocketAddress& addr);
	int send(const void *msg, unsigned len);
	int recv(void *buf, size_t len);

	virtual int underflow();
	virtual int overflow(int ch);
	virtual int sync();

	StreamSocket(int bufsize);

	void accept(StreamServerSocket& s);
	void accept(StreamServerSocket& s, SocketAddress& a);
			
	friend class StreamServerSocket;
};

/// Listener for streamable sockets.
class StreamServerSocket : virtual public Socket
{
	public:
	virtual ~StreamServerSocket();

	protected:
	
	void accept(StreamSocket& sock, SocketAddress& addr);
	void accept(StreamSocket& sock);
	void prepare(const SocketAddress& addr, int backlog);
	
	StreamServerSocket();

	friend class StreamSocket;
};

inline void StreamSocket::accept(StreamServerSocket& s)
{
	s.accept(*this);
}

inline void StreamSocket::accept(StreamServerSocket& s, SocketAddress& a)
{
	s.accept(*this,a);
}

/// IP Socket manipulator
class IPSocket : virtual public Socket
{
	public:
	virtual ~IPSocket();

	/** If  enabled  the IP_TOS ancillary message is passed
	    with incoming packets. It  contains  a  byte  which
	    specifies  the  Type of Service/Precedence field of
	    the packet header.
	*/
	void setRecvTOS(bool tos = true);

	/// Is RecvTOS option enabled ?
	bool getRecvTOS();

	/** When  this  flag  is  set pass a IP_RECVTTL control
            message with the time to live field of the received
            packet  as  a  byte.  Not supported for streamable sockets.
	*/
	void setRecvTTL(bool recvttl = true);

	/// Is RecvTTL flag enabled?
	int getRecvTTL();
	
	/// Set time to live field for packets.
	void setTTL(int ttl);

	/// Get current time to live value.
	int getTTL();

	/// Supported Types Of Service
	enum tos {
		lowdelay, ///< Minimize delays in packet delivery.
		throughput, ///< Maximize throughput.
		reliability, ///< Maximize reliability.
		mincost ///< Minimize costs.
	};
	
	/// Set Type Of Service.
	void setTOS(tos t);

	/// Get Type Of Service.
	tos getTOS();

	/// Get MTU (max transfer unit) for connected socket.
	int getMTU();

	protected:
	IPSocket();
};

/// TCP Server socket.
class TCPSocket : virtual public IPSocket, virtual public StreamServerSocket
{
	public:
	/// Construct TCP server bind to address with specified backloged connections.
	TCPSocket(const SocketAddress &bind, int backlog = 16);
	/// construct TCP server, initiate listening, do not bind! - for external wrappers
	TCPSocket(int ext_sock, int backlog = 16);

	/// Destroy TCP server.
	virtual ~TCPSocket();
};

/// TCP socket stream.
class TCPStream : virtual public IPSocket, virtual public StreamSocket
{
	public:
	/** Connect to remote host.
	  @param dst Destination host.
	  @param connto Timeout for this socket.
	  @param bufsize Size of stream buffers.
	*/
	TCPStream(const SocketAddress &dst, unsigned connto = 30000, int bufsize = 2048);
	/// Connect to remote host from specific local address. bind is a local address.
	TCPStream(const SocketAddress &dst, const SocketAddress &bind, unsigned connto = 30000, int bufsize = 2048);

	/// Accept connection from TCP stream server.
	TCPStream(TCPSocket& acpt, int bufsize = 2048);

	/// Accept connection from TCP stream server with recognition of peer address.
	TCPStream(TCPSocket& acpt, SocketAddress& peer, int bufsize = 2048);

	/// Destroys TCP stream.
	virtual ~TCPStream();

	static void flushCounters();
	static unsigned connAccept();
	static unsigned connConnect();
	static unsigned bytesWrite();
	static unsigned bytesRead();

	protected:
	/// Create unconnected TCP stream.
	TCPStream(int bufsize = 2048);
};

};

struct ssl_st;
struct ssl_ctx_st;

typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;

namespace handylib {

/// TCP SSL stream.
class TCPSSLStream : public TCPStream
{
	SSL *ssl;
	SSL_CTX *ctx;
	bool isClient;
	public:
	TCPSSLStream(const SocketAddress &dst, const char *certname, const char *keyname = (const char*)0, unsigned connto = 30000, int bufsize = 2048);
	/** Connect to remote host using SSL.
	  @param dst Destination host.
	  @param connto Timeout for this socket.
	  @param bufsize Size of stream buffers.
	*/
	TCPSSLStream(const SocketAddress &dst, unsigned connto = 30000, int bufsize = 2048);
	/// Connect to remote host from specific local address. bind is a local address.
	TCPSSLStream(const SocketAddress &dst, const SocketAddress &bind, unsigned connto = 30000, int bufsize = 2048);
	/// Accept connection from TCP stream server using SSL.
	TCPSSLStream(TCPSocket& acpt, const char *certname, const char *keyname = (const char*)0, int bufsize = 2048);
	/// Accept connection from TCP stream server using SSL with recognition of peer address.
	TCPSSLStream(TCPSocket& acpt, SocketAddress& peer, const char *certname, const char *keyname = (const char*)0, int bufsize = 2048);
	/// Accept postponed TCP stream server with recognition of peer address.
	TCPSSLStream(TCPSocket& acpt, SocketAddress& peer, int bufsize = 2048);
	/// Accept postponed TCP stream server.
	TCPSSLStream(TCPSocket& acpt, int bufsize = 2048);

	/// Destroys SSL stream.
	virtual ~TCPSSLStream();

	SSL *get_ssl() const { return ssl; }
	SSL_CTX *get_sslctx() const { return ctx; }

	/// Use for postponed connect
	void ssl_connect();

	/// Use for postponed connect with certificate
	void ssl_connect(const char *certname, const char *keyname);

	/// Use for postponed accept
	void ssl_accept(const char *certname, const char *keyname);

	protected:
	int ssl_send(const void *msg, unsigned len);
	int ssl_recv(void *buf, size_t len);

	virtual int underflow();
	virtual int overflow(int ch);
	virtual int sync();

	/// Create unconnected TCP SSL Stream.
	TCPSSLStream(int bufsize = 2048);
};

/// UDP Socket.
class UDPSocket : public IPSocket
{
	public:
	/// Creates UDP socket.
	UDPSocket();

	/// Destroys UDP socket.
	virtual ~UDPSocket();
};

/// UNIX domain socket manipulator.
class UnixSocket : virtual public Socket
{
	public:
	/// Destroy socket.
	virtual ~UnixSocket();

	int getPeerPID(); ///< Return process ID of peer.
	int getPeerUID(); ///< Return user ID of peer.
	int getPeerGID(); ///< Return group ID of peer.
	/** Get remote process info.
	  @param pid If pid is not null, then it is a process ID of remote process.
	  @param uid If uid is not null, then it is a user ID of remote process.
	  @param gid If gid is not null, then it is a group ID of remote process.
	 */
	void getPeer(int *pid, int *uid, int *gid);
	protected:
	/// Constructor.
	UnixSocket();
};

/// Create UNIX datagram socket.
class UnixDatagramSocket : public UnixSocket
{
	public:
	/// Constructor.
	UnixDatagramSocket();
	/// Destructor.
	virtual ~UnixDatagramSocket();
};

/// UNIX stream server.
class UnixStreamServer : virtual public UnixSocket, virtual public StreamServerSocket
{
	public:
	/// Server listens on specified address.
	UnixStreamServer(const SocketAddress& addr, int backlog = 16);

	/// Destroy UNIX stream server.
	virtual ~UnixStreamServer();
};

/// UNIX domain sockets stream.
class UnixStream : virtual public UnixSocket, virtual public StreamSocket
{
	public:
	/// Connect to another process.
	UnixStream(const SocketAddress& addr, unsigned connto = 30000, int bufsize = 2048);
	/// Wait for new connection.
	UnixStream(UnixStreamServer& str, int bufsize = 2048);

	/// Destroy UNIX stream socket.
	virtual ~UnixStream();
};

};

#endif

#include <string>
#include <map>
#include <functional>

namespace handylib {

struct HTTPHeaderStringCmp : public std::binary_function<std::string,std::string,bool> {
  bool operator()(const std::string& x, const std::string& y) const;
};

/// HTTP Cookie value object.
class HTTPCookie
{
	std::string value, domain, path;
	Time expire;
	public:
	/// Create cookie value.
	HTTPCookie() { }
	/// Create cookie value.
	HTTPCookie(const std::string& v) { value = v; }
	/// Create cookie value.
	HTTPCookie(const std::string& v, const Time& e) { value = v; expire = e; }
	/// Create cookie value.
	HTTPCookie(const std::string& v, const Time& e, const std::string& d) { value = v; domain = d; expire = e; }
	/// Create cookie value.
	HTTPCookie(const std::string& v, const Time& e, const std::string& d, const std::string& p)
	{ value = v; domain = d; path = p; expire = e; }
	/// Cookie copy constructor.
	HTTPCookie(const HTTPCookie& c) : value(c.value), domain(c.domain), path(c.path), expire(c.expire) { }

	/// Copy operator.
	HTTPCookie& operator = (const HTTPCookie& c) { value = c.value; domain = c.domain; path = c.path; expire = c.expire; return *this; }

	const std::string& getValue() const { return value; } ///< Get value.
	const std::string& getDomain() const { return domain; } ///< Get domain.
	const std::string& getPath() const { return path; } ///< Get path.
	const Time& getExpire() const { return expire; } ///< Get expiration.
	void setValue(const std::string& x) { value = x; } ///< Set value.
	void setDomain(const std::string& x) { domain = x; } ///< Set domain.
	void setPath(const std::string& x) { path = x; } ///< Set path.
	void setExpire(const Time& e) { expire = e; } ///< Set expiration.

	/// Erase cookie values
	void erase() { value.resize(0); domain.resize(0); path.resize(0); expire = Time(); }
};

/// HTTP Cookies.
class HTTPCookies : public std::map<std::string,HTTPCookie>
{
	bool client;
	public:
	HTTPCookies(bool cl = true) : std::map<std::string,HTTPCookie>() { client = cl; }
	~HTTPCookies() { }

	/// Get cookies for server
	std::string getCookies() const;

	/// Get cookie for client
	std::string getCookie(const_iterator i, const std::string& dom) const;

	/// Load cookies from client. (Cookie: header).
	void loadCookies(const char *s);

	/// Load cookie from server. (Set-Cookie: header).
	void loadCookie(const char *s);
};

/// Streambuf for limited input.
class HTTPILimitBuf : public std::streambuf
{
	std::streambuf& i;
	int lim;
	char *cbuf;
	int csize;
	public:
	HTTPILimitBuf(std::streambuf& i, int limit);
	virtual ~HTTPILimitBuf();

	protected:
	virtual int sync(void);
	virtual int underflow(void);
};

/// Streambuf for chunked HTTP input.
class HTTPIChunkedBuf : public std::streambuf
{
	std::streambuf& i;
	char *cbuf;
	int cleft, csize;
	std::streampos pos;
	public:
	HTTPIChunkedBuf(std::streambuf& i);
	virtual ~HTTPIChunkedBuf();

	protected:
	virtual int sync(void);
	virtual int underflow(void);
};

/// Streambuf for chunked HTTP output.
class HTTPOChunkedBuf : public std::streambuf
{
	std::streambuf& o;
	char *cbuf;
	std::streampos pos;
	public:
	HTTPOChunkedBuf(std::streambuf& o);
	virtual ~HTTPOChunkedBuf();
	void mysync() { sync(); }

	protected:
	virtual int sync(void);
	virtual int overflow(int ch);
};

class igzstreambuf;

/// Tiny HTTP client (knows HTTP digest/basic authentification).
class HTTPClient : public std::istream
{
	IPAddress proxy;
	int status;
	bool is_11;
	unsigned to;
	std::string url;
	IPAddress last;
	std::string last_host;
	std::streambuf *chunkbuf;
	TCPStream *tcp;
	HTTPClient(const HTTPClient& h);
	HTTPClient& operator = (const HTTPClient& h);
	public:
	/// Initialize empty HTTP client.
	HTTPClient() : std::istream(0) { status = 0; is_11 = true; to = 30000; tcp = (TCPStream*)0; chunkbuf = (HTTPIChunkedBuf*)0; }
	
		/// Initialize HTTP client with proxy.
	HTTPClient(const IPAddress& p) : std::istream(0) { proxy = p; status = 0; is_11 = true; to = 30000;  tcp = (TCPStream*)0; chunkbuf = (HTTPIChunkedBuf*)0; }

	/// Get TCP stream
	TCPStream *get_tcp() { return tcp; }

	/// Set timeout
	void setTimeout(unsigned t) { to = t; }

	/// Destroy HTTP client.
	virtual ~HTTPClient();

	/// Clone HTTP object. dispose with delete operator.
	virtual HTTPClient* clone();

	/// Request HTTP headers.
	std::map<std::string,std::string,HTTPHeaderStringCmp> rh;

	/// Returned HTTP headers.
	std::map<std::string,std::string,HTTPHeaderStringCmp> th;

	/// Query parameters (post/get).
	std::map<std::string,std::string> pr;

	/// Input cookies.
	HTTPCookies ic;

	/// Output cookies.
	HTTPCookies oc;

	/// Perform HTTP request to client. If post is true, then request method will be POST.
	void request(const std::string& url, bool post = false, bool head = false);

	/// Link _preserves_ Referer, Cookies from previous request. Automatically processes 3xx answer. If post is true, then request method will be POST.
	void link(const std::string& url, bool post = false, bool head = false);

	/// Disconnect from remote host. (if still connected).
	void disconnect();

	/// Is proxy server enabled.
	bool isProxy() const { if (proxy.getPort()) return true; return false; }

	/// Close connection immediately.
	void setClose() { rh["Connection"] = "close"; rh["no-chunked-encoding"] = "1"; }

	/// Is HTTP/1.1 accepted.
	bool is11() const { return is_11; }

	/// Switch HTTP/1.1 or HTTP/1.0 protocol.
	void set10(bool i = false) { is_11 = i; }

	/// Get proxy server.
	const IPAddress& getProxy() const { return proxy; }

	/// Set proxy server.
	void setProxy(const IPAddress& ip) { proxy = ip; }

	/// Get timestamp.
	Time getTimestamp(const std::string& h = "Date");

	/// Make timestamp.
	std::string makeTimestamp(const Time& t);

	/// Get request status. -1 = fatal error.
	int getStatus() const { return status; }

	/// Is request was successful?
	bool isOK() { return status == 200; }
	
	protected:
	/// Create new TCPStream connected to remote host. Used in child classes for example to provide socksified HTTP access.
	virtual TCPStream *connect(const IPAddress& host, unsigned to, int size);
	
	/// Create new TCPStream connected to remote host. Used in child classes for example to provide socksified HTTP access.
	virtual TCPStream *connect_ssl(const IPAddress& host, unsigned to, int size);
	
	/// Copy src object.
	virtual void copy(const HTTPClient& src);
};

class ogzstreambuf;

/// HTTP Server processing (server-side CGI or tiny HTTP server).
class HTTPServer : public std::ostream
{
	protected:
	bool get_request_method, head_only, is_10;
	std::string path;
	std::string remote_user;
	std::string query_string;
	std::string server_name;
	IPAddress peer_address;
	int status, server_port, max_request_size;
	
	TCPStream *tcp;
	HTTPOChunkedBuf *chunkbuf;
	std::streambuf *strbuf;
	
	std::istream& input;
	std::ostream& real_output;

	bool do_shutdown;

	Time last_modified;
	bool block_content;

	void checkLastModified();

	private:

	char *parseBoundary(char *buf, int maxs);
	unsigned loadMultipartBuf(std::istream& i, char *buf, int maxs);
	void loadMultipart(std::istream& i);
	
	void loadParams();

	HTTPServer(const HTTPServer& s);
	HTTPServer& operator =(const HTTPServer& s);

	public:
	/// Parse CGI inputs.
	HTTPServer(int maxr = 0);
	/// Just accept connection - DO NOT PARSE ANYTHING, parse later by accept()
	HTTPServer(TCPSocket& sock);
	/// Just open with initiated tcp stream.
	HTTPServer(TCPStream* sock);
	/// Just accept SSL connection - DO NOT PARSE ANYTHING, parse later by accept()
	HTTPServer(TCPSocket& sock, const char *certname, const char *keyname);
	/// Accept connection (HTTP).
	HTTPServer(TCPSocket& sock, const std::string& sname, int sport = 80, int maxr = 0);
	/// Accept connection (HTTPS).
	HTTPServer(TCPSocket& sock, const std::string& sname,  const char *certname, const char *keyname = (const char *)0, int sport = 443, int maxr = 0);
	/// Serve already connected (HTTP).
	HTTPServer(TCPStream* sock, const std::string& sname, int sport = 80, int maxr = 0);
	/// Serve already connected (HTTPS).
	HTTPServer(TCPStream* sock, const std::string& sname,  const char *certname, const char *keyname = (const char *)0, int sport = 443, int maxr = 0);
	/// Delete object.
	~HTTPServer();

	/// Use with care.
	TCPStream *get_tcp() { return tcp; }

	/// Set dirty socket shutdown
	void setShutdown() { do_shutdown = true; }

	/// Accept connection (connection is in tcp)
	void accept(const std::string& sname, int sport = 80, int maxr = 0);
	
	/// GET or POST parameters parsed.
	std::map<std::string,std::string> h;

	/// Request headers.
	std::map<std::string,std::string,HTTPHeaderStringCmp> rh;

	/// Response headers.
	std::map<std::string,std::string,HTTPHeaderStringCmp> th;

	/// Filenames for multipart/form-data encoding.
	std::map<std::string,std::string> fn;

	/// Cookies.
	HTTPCookies c;

	/// Set timeout for TCP
	void setTimeout(unsigned to) { if (tcp) tcp->setTimeout(to); }

	/// Set result status.
	void setStatus(int st) { status = st; }

	/// Get result status. -1 = fatal error.
	int getStatus() const { return status; }

	/// Set Server Name
	void setServerName(std::string sname, int prt);

	/// Initiate stream.
	void beginData();

	/// Do not cache
	void nocache() { th["Pragma"] = "no-cache"; th["Cache-Control"] = "no-cache"; }

	/// Do not store
	void nostore() { th["Pragma"] = "no-cache"; th["Cache-Control"] = "no-store"; }

	/// Store forever (never expires)
	void store() { th["Expires"] = "Sat, 23-Nov-2010 14:11:20 GMT"; }
	
	/// Returns true when connection is established.
	bool isConnected() const { return tcp != 0 && tcp->err == Socket::OK; }
	
	/// Close connection after this request.
	void setClose() { rh["Connection"] = "close"; }

	/// Request authentification (401 response)
	void requestBasicAuth(const std::string& realm);

	/// Get authenticated user's username.
	const std::string& getRemoteUser() { return remote_user; }
	/// Get remote useragent.
	std::string getUserAgent() { return rh["User-Agent"]; }
	/// Get request method (GET or POST, uppercase), true means GET.
	bool getRequestMethod() { return get_request_method; }
	/// Get script path (after script name).
	const std::string& getPath() const { return path; }
	/// Set script path (useful for internal redirects).
	void setPath(const std::string& s) { path = s; }
	/// Get query std::string.
	const std::string& getQueryString() { return query_string; }
	/// Get HTTP referer.
	std::string getReferer() { return rh["Referer"]; }
	/// Get remote address.
	const IPAddress& getRemoteAddress() { return peer_address; }
	/// Set remote address.
	void setRemoteAddress(const IPAddress& addr) { peer_address = addr; }
	/// Get server name
	const std::string& getServerName() { return server_name; }
	/// Set server name
	void setServerName(const std::string& s) { server_name = s; }
	/// Get server port
	int getServerPort() { return server_port; }
	/// Get current URL without script name and the rest.
	std::string getDirURL(bool https = false);
	/// Get current URL without query std::string.
	std::string getBaseURL(bool https = false);
	/// Get current URL.
	std::string getFullURL(bool https = false);
	/// Set last modified (do it before beginData()).
	void setLastModified(const Time& t) { last_modified = t; }
	/// Get last modified.
	Time getLastModified() { return last_modified; }

	/// Complete flush (for chunked encoding)
	void fullflush();
	
	/// Finish request.
	void endRequest();
};

/// URL escape std::string sequence (spaces are replaced with + and non-URL characters with %xx notation).
std::string urlescape(const std::string& s);

/// URL unescape std::string sequence (reverses effect of urlescape).
std::string urlunescape(const std::string& s);

/// HTMLize std::string (all dangerous characters like <, >, ... are escaped).
std::string htmlize(const std::string& s);

/// insert ... into the middle of the std::string to make it not longer than specified chars.
inline std::string htmlstrip(const std::string& s, unsigned sz) {
	if (s.size() <= sz) return s;
	if (sz <= 5) return s;
	sz -= 3; sz /= 2;
	return s.substr(0,sz)+"..."+s.substr(s.size()-sz);
}

inline std::string htmltip(const std::string& s, unsigned sz) {
	return "<a href=\"#\" onMouseover=\"showtip(this,event,'"+htmlize(s)+"'); return true;\" onMouseOut=\"hidetip(); return true;\">" + htmlize(htmlstrip(s,sz)) + "</a>";
}
inline std::string htmltipref(const std::string& s, const std::string& href, unsigned sz) {
	return "<a href=\""+href+"\" onMouseover=\"showtip(this,event,'"+htmlize(s)+"'); return true;\" onMouseOut=\"hidetip(); return true;\">" + htmlize(htmlstrip(s,sz)) + "</a>";
}
inline std::string htmltip(const std::string& s, const std::string& s1) {
	return "<a href=\"#\" onMouseover=\"showtip(this,event,'"+s+"'); return true;\" onMouseOut=\"hidetip(); return true;\">" + s1 + "</a>";
}

};

#endif
