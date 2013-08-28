#include "handylib.h"

#include <iomanip>
#include <sstream>
#include <strstream>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/un.h>

#if HAVE_SSL
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#ifndef __USE_MISC
#define __USE_MISC
#endif
#include <pthread.h>
#include <sys/time.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/poll.h>
#include <errno.h>

#include <sstream>
#include <iomanip>
#include <stdlib.h>

#include <ctype.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

using namespace std;

namespace handylib {

bool HTTPHeaderStringCmp::operator()(const string& x, const string& y) const
{
	return strcasecmp(x.c_str(),y.c_str()) < 0;
}

string HTTPCookies::getCookies() const
{
	string s;
	HTTPCookies::const_iterator i;
	for (i = begin(); i != end(); i++) {
		if (i != begin()) s += "; ";
		s += i->first;
		s += "=";
		s += i->second.getValue();
	}
	return s;
}

string HTTPCookies::getCookie(HTTPCookies::const_iterator i, const string& dom) const
{
	string s = i->first;

	s += "="; s += i->second.getValue();
	s += "; domain=";
	if (i->second.getDomain().empty()) s += dom;
	else s += i->second.getDomain();
	s += "; path="; 
	if (i->second.getPath().empty()) s += "/";
	else s += i->second.getPath();

	if (i->second.getExpire().seconds()) {
		s += "; expires=";
		Time x(i->second.getExpire());
		s += x.formatHTTP();
	} else { s += "; expires=0"; }

	return s;
}

void HTTPCookies::loadCookies(const char *s)
{
	const char *ep, *np, *enp;

	np = s;
	while (*np) {
		while ((*np == ';' || *np == ' ' || *np == '\t') && *np) np++;
		if (!*np) break;
		enp = np;
		while (*enp && *enp != '=') enp++;
		if (!*enp) break;
		ep = enp;
		while (*ep && *ep != ';') ep++;
		string name(np, enp-np);
		string value(enp+1, ep-enp-1);
		(*this)[name] = HTTPCookie(value);
		np = ep;
	}
}

void HTTPCookies::loadCookie(const char *s)
{
	const char *ep, *np, *enp;
	HTTPCookies::iterator i;
	string name;
	bool hasn = false;

	np = s;
	while (*np) {
		while ((*np == ';' || *np == ' ' || *np == '\t') && *np) np++;
		if (!*np) break;
		enp = np;
		while (*enp && *enp != '=') enp++;
		if (!*enp) break;
		ep = enp;
		while (*ep && *ep != ';') ep++;
		if (!strncasecmp(np,"path",enp-np) && hasn) {
			string value(enp+1, ep-enp-1);
			i->second.setPath(value);
		} else if (!strncasecmp(np,"domain",enp-np) && hasn) {
			string value(enp+1, ep-enp-1);
			i->second.setDomain(value);
		} else if (!strncasecmp(np,"expires",enp-np) && hasn) {
			Time t;
			t.parseHTTP(enp+1);
			i->second.setExpire(t);
		} else {
			hasn = true;
			string name(np, enp-np);
			string value(enp+1, ep-enp-1);
			(*this)[name] = HTTPCookie(value);
			i = find(name);
		}
		np = ep;
	}
}

HTTPILimitBuf::HTTPILimitBuf(streambuf& ib, int limit) : i(ib), lim(limit)
{
	cbuf = new char[1024];
	if (!cbuf) return;
	csize = 1024;
}
HTTPILimitBuf::~HTTPILimitBuf()
{
	if (cbuf) delete [] cbuf;
}

int HTTPILimitBuf::sync(void) { return 0; }
int HTTPILimitBuf::underflow(void)
{
	if (!cbuf) return EOF;
	if (gptr() < egptr()) return (unsigned char)*gptr();
	if (lim <= 0) return EOF;
	int len = 0;

	if (lim > csize) len = i.sgetn(cbuf,csize);
	else len = i.sgetn(cbuf,lim);
	lim -= len;
	setg(cbuf,cbuf,cbuf+len);
	if (len <= 0) return EOF; // premature end of data

	return (unsigned char)*gptr();
}

HTTPIChunkedBuf::HTTPIChunkedBuf(streambuf& is) : i(is)
{
	csize = 1024; cleft = 0; pos = 0;
	cbuf = new char[csize];
	
	if (!cbuf) return;
	setg(cbuf,cbuf,cbuf);
}

HTTPIChunkedBuf::~HTTPIChunkedBuf()
{
	if (cbuf) delete [] cbuf;
}

int HTTPIChunkedBuf::underflow(void)
{
	if (!cbuf) return EOF;
	if (gptr() < egptr())
		return (unsigned char)*gptr();

	pos += gptr() - eback();
	setg(cbuf,cbuf,cbuf);

	for (;;) {
		if (cleft > 0) {
			int p;
			if (cleft >= csize) {
				p = i.sgetn(cbuf,csize);
			} else {
				p = i.sgetn(cbuf,cleft+1);
				if (p == cleft+1) p--;
			}
			if (p <= 0) return EOF;
			cleft -= p;
			pos += gptr() - eback();
			setg(cbuf,cbuf,cbuf+p);
			return (unsigned char)*gptr();
		}

		char s[8];
		int ix = 0, c;

		while ((c = i.sbumpc()) != EOF && ix < 7) {
			if (c == '\n' && ix > 0) break;
			if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
			s[ix++] = c;
		}
		s[ix] = 0;
		
		if (ix == 0) return EOF;
		if (s[0] == '0' && !s[1]) return EOF;

		sscanf(s,"%x",&ix);

		if (ix < 0) ix = 0;

		if (ix == 0) return EOF;

		cleft = ix;
	}

	return EOF;
}

int HTTPIChunkedBuf::sync(void)
{
	return 0;
}

HTTPOChunkedBuf::HTTPOChunkedBuf(streambuf& os) : o(os)
{
	cbuf = new char[1027]; pos = 0;
	if (!cbuf) return;
	setp(cbuf,cbuf+1024);
}

HTTPOChunkedBuf::~HTTPOChunkedBuf()
{
	overflow(EOF);
	o.sputn("0\r\n",3);
	if (cbuf) delete cbuf;
}

int HTTPOChunkedBuf::sync(void)
{
	return overflow(EOF);
}

int HTTPOChunkedBuf::overflow(int ch)
{
	if (!cbuf) return EOF;
	streamsize len = pptr() - pbase();
	if (ch != EOF) { *pptr() = ch; pptr()[1] = '\r'; len++; pptr()[2] = '\n'; len++; }
	else { *pptr() = '\r'; len++; pptr()[1] = '\n'; }
	char p[8];
	snprintf(p,6,"%x\r\n",len-1);
	o.sputn(p,strlen(p));
	pos += len;
	setp(cbuf,cbuf+1024);
	if (o.sputn(cbuf,len+1) != len+1) return EOF;
	return 0;
}

HTTPClient::~HTTPClient()
{
	disconnect(); 

	if (tcp) delete tcp;
	tcp = (TCPStream*)0;
}

HTTPClient* HTTPClient::clone()
{
	HTTPClient *x = new HTTPClient();
	if (!x) return (HTTPClient*)0;
	x->copy(*this);
	return x;
}

void HTTPClient::copy(const HTTPClient& s)
{
	proxy = s.proxy;
	status = s.status;
	is_11 = s.is_11;
	url = s.url;
	chunkbuf = (streambuf*)0;
	tcp = (TCPStream*)0;
	rh = s.rh;
	th = s.th;
	pr = s.pr;
	ic = s.ic;
	oc = s.oc;
}

void HTTPClient::request(const string& u, bool post, bool head)
{
	string query;
	string::const_iterator cu, cue;
	map<string,string>::const_iterator cip;
	map<string,string,HTTPHeaderStringCmp>::const_iterator hip;

	disconnect();
	url = u;
	bool https = false;
	if (post && pr.find("multipart/form-data") == pr.end())
		rh["Content-Type"] = "application/x-www-form-urlencoded";

	if (pr.find("_full_post") == pr.end()) {
		for (cip = pr.begin(); cip != pr.end(); cip++) {
			if (cip != pr.begin()) query += "&";
			query += urlescape(cip->first);
			query += "=";
			query += urlescape(cip->second);
		}
	} else {
		query = pr["_full_post"];
	}

	cu = url.begin();
	if (cu == url.end() || (*cu != 'H' && *cu != 'h')) return;
	cu++; if (cu == url.end() || (*cu != 'T' && *cu != 't')) return;
	cu++; if (cu == url.end() || (*cu != 'T' && *cu != 't')) return;
	cu++; if (cu == url.end() || (*cu != 'P' && *cu != 'p')) return;
	cu++; if (cu == url.end()) return;
	if (*cu == 'S' || *cu == 's') { cu++; https = true; }
       	if (cu == url.end() || *cu != ':') return;
	cu++; if (cu == url.end() || *cu != '/') return;
	cu++; if (cu == url.end() || *cu != '/') return;
	
	for (cue = ++cu; cue != url.end() && *cue != ':' && *cue != '/'; cue++);
	string host(cu,cue);
	bool hsw = false;
	if (rh.find("Host") == rh.end() && is_11) { rh["Host"] = host; hsw = true; }
	string port(https?"443":"80");
	if (cue != url.end() && *cue == ':') {
		cu = cue;
		for (cue = ++cu; cue != url.end() && *cue != ':' && *cue != '/'; cue++);
		port = string(cu,cue);
		if (hsw) rh["Host"] += string(cu-1,cue);
	}
	string path("/");
	if (cue != url.end() && *cue == '/') path = string(cue,static_cast<string::const_iterator>(url.end()));
	if (rh.find("Accept") == rh.end()) rh["Accept"] = "*/*";
	if (post && pr.find("multipart/form-data") != pr.end()) {
		char s[16];
		snprintf(s,16,"%u",pr["multipart/form-data"].size());
		rh["Content-Length"] = string(s);
	} else if (post && query.size() > 0) {
		char s[16];
		snprintf(s,16,"%u",query.size());
		rh["Content-Length"] = string(s);
	} else { rh.erase("Content-Length"); }

	if (oc.begin() != oc.end())
		rh["Cookie"] = oc.getCookies();
	else
		rh.erase("Cookie");

	string headers;
	for (hip = rh.begin(); hip != rh.end(); hip++) {
		if (hip->second.size() < 1) continue; // Do not emit empty header
		headers += hip->first;
		headers += ": ";
		headers += hip->second;
		headers += "\r\n";
	}

	string request;
	IPAddress dst;
	if (isProxy()) { // we have a proxy server
		dst = proxy;
		last_host.resize(0);
	} else if (!dst.set(host,port)) { // need to resolve
		if (host == "localhost") {
			int p = dst.getPort();
			dst = IPAddress("127.0.0.1");
			dst.setPort(p);
			last_host = host;
		} else if (last_host == host) dst = last;
		else return;
	} else last_host.resize(0);
	if (dst.getIP() == 0) return;

	bool try_keep = false;
	if (last == dst && last.getPort() == dst.getPort() && rh["Connection"] != "close") try_keep = true;
	last = dst;
	
	if (post) request = "POST "; else if (!head) request = "GET "; else request = "HEAD ";
	if (isProxy()) {
		request += "http://"; 
		request += host;
		request += ":";
		request += port;
	}
	request += path;
	if (!post && query.size() != 0) {
		request += "?";
		request += query;
	}
	if (is_11) request += " HTTP/1.1\r\n"; else request += "HTTP/1.0\r\n";
	request += headers;
	request += "\r\n";
	if (post && pr.find("multipart/form-data") != pr.end())
		request += pr["multipart/form-data"];
	else if (post && query.size() > 0) request += query;

	if (tcp && (!tcp->good() || !try_keep)) {
		if (!isProxy() && !dst.set(host,port)) {
			status = -1; disconnect(); return;
		}
		TCPStream *x = tcp;
		tcp = (TCPStream*)0;
		if (x) delete x;
	}
	if (!tcp) {
		if (!https) tcp = connect(dst,to,2048);
		else tcp = connect_ssl(dst,to,2048);
		try_keep = false;
	}
	if (!tcp) { status = -1; disconnect(); return; }
	if (tcp->err != Socket::OK) { status = -1; disconnect(); return; }
	*tcp << request;

	tcp->flush();
	if (tcp->err != Socket::OK) { status = -1; disconnect(); return; }
	do {
		status = 0;
		while (tcp->peek() == '\n' || tcp->peek() == '\r' || tcp->peek() == ' ' || tcp->peek() == '\t') tcp->get();
		if (tcp->get() != 'H') {
			if (try_keep) {
				TCPStream *x = tcp;
				tcp = (TCPStream*)0;
				if (x) delete x;
				if (!isProxy() && !dst.set(host,port)) {
					status = -1; disconnect();
					return;
				}
				if (!https) tcp = connect(dst,to,2048);
				else tcp = connect_ssl(dst,to,2048);
				if (!tcp) { status = -1; disconnect(); return; }
				if (tcp->err != Socket::OK) { status = -1; disconnect(); return; }
				*tcp << request;
				tcp->flush();
				if (tcp->err != Socket::OK) { status = -1; disconnect(); return; }
				try_keep = false;
				while (tcp->peek() == '\n' || tcp->peek() == '\r' || tcp->peek() == ' ' || tcp->peek() == '\t') tcp->get();
				if (tcp->get() != 'H') { status = -1; disconnect(); return; }
			} else { status = -1; disconnect(); return; }
		}
		if (tcp->get() != 'T') { status = -1; disconnect(); return; }
		if (tcp->get() != 'T') { status = -1; disconnect(); return; }
		if (tcp->get() != 'P') { status = -1; disconnect(); return; }
		while (tcp->peek() == '\n' || tcp->peek() == '\r' || tcp->peek() == ' ' || tcp->peek() == '\t') tcp->get();
		if (tcp->get() != '/') { status = -1; disconnect(); return; }
		if (tcp->get() != '1') { status = -1; disconnect(); return; }
		if (tcp->get() != '.') { status = -1; disconnect(); return; }
		tcp->get();
		while (tcp->peek() == '\n' || tcp->peek() == '\r' || tcp->peek() == ' ' || tcp->peek() == '\t') tcp->get();
		status = (tcp->get() - '0')*100;
		status += (tcp->get() - '0')*10;
		status += tcp->get() - '0';
		if (status < 100 || status > 600) { status = 0; { status = -1; disconnect(); return; } }
		while (tcp->peek() == '\n' || tcp->peek() == '\r' || tcp->peek() == ' ' || tcp->peek() == '\t') tcp->get();
		while (!tcp->eof() && tcp->get() != '\n');

		th.clear();
		while (!tcp->eof() && tcp->peek() != '\n' && tcp->peek() != '\r') {
			string n, v;
			while (!tcp->eof() && tcp->peek() != ':' && tcp->peek() != '\n' && tcp->peek() != '\r') n += (char)tcp->get();
			if (tcp->peek() == ':') {
				while (tcp->peek() == ':' || tcp->peek() == ' ' || tcp->peek() == '\t') tcp->get();
				while (!tcp->eof() && tcp->peek() != '\n' && tcp->peek() != '\r') v += (char)tcp->get();
				if (!strcasecmp(n.c_str(),"Set-Cookie")) ic.loadCookie(v.c_str());
				th[n] = v;
			} else break;
			if (tcp->peek() == '\r') tcp->get();
			if (tcp->peek() == '\n') tcp->get();
			if (tcp->peek() == '\r' || tcp->peek() == '\n') break;
		}
		while (tcp->peek() == '\n' || tcp->peek() == '\r') tcp->get();
	} while (status == 100);

	if (th.find("Transfer-Encoding") != th.end()) {
		chunkbuf = new HTTPIChunkedBuf(*tcp);
		if (!chunkbuf) { status = -1; disconnect(); return; }
		rdbuf(chunkbuf);
	} else if (th.find("Content-Length") != th.end()) {
		int len = atoi(th["Content-Length"].c_str());
		if (len > 0) {
			chunkbuf = new HTTPILimitBuf(*tcp, len);
			if (!chunkbuf) { status = -1; disconnect(); return; }
			rdbuf(chunkbuf);
		} else {
			th["Connection"] = "close";
			rdbuf(tcp->rdbuf());
		}
	} else {
		th["Connection"] = "close";
		rdbuf(tcp->rdbuf());
	}
}

void HTTPClient::link(const string& u, bool post, bool head)
{
	rh["Referer"] = url;
	ic = oc;
	request(u,post,head);
	while (status % 100 == 3 && th.find("Location") != th.end()) {
		pr.clear();
		rh["Referer"] = url;
		ic = oc;
		request(th["Location"],false,head);
	}
}

void HTTPClient::disconnect()
{
	rdbuf((streambuf*)0);
	if (chunkbuf) delete chunkbuf;
	chunkbuf = (streambuf*)0;
	if ((th.find("Connection") != th.end() && th["Connection"] == "close") || status < 0) {
		TCPStream *x = tcp;
		tcp = (TCPStream*)0;
		if (x) delete x;
	}
	status = 0;
}

string HTTPClient::makeTimestamp(const Time& t)
{
	Time tm(t); return tm.formatHTTP();
}

Time HTTPClient::getTimestamp(const string& s)
{
	string tp = rh[s];
	Time t; t.parseHTTP(tp.c_str());
	return t;
//	if (tp.empty()) return Time();
//	if (tp[3] == ',') return Time("%a, %d %b %Y %H:%M:%S",tp.c_str(),true);
//	if (tp[3] == ' ') return Time("%a %b %d %H:%M:%S %Y",tp.c_str(),true);
//	return Time("%A, %d-%b-%y %H:%M:%S",tp.c_str(),true);
}

TCPStream *HTTPClient::connect(const IPAddress& host, unsigned to, int size)
{
	return new TCPStream(host,to,size);
}

TCPStream *HTTPClient::connect_ssl(const IPAddress& host, unsigned to, int size)
{
	return new TCPSSLStream(host,to,size);
}

void HTTPServer::requestBasicAuth(const string& realm)
{
	setStatus(401);
	th["WWW-Authenticate"] = "Basic realm=\""+realm+"\"";
}

char *HTTPServer::parseBoundary(char *bboundary, int maxs)
{
	char *boundary,*p;
	if (rh["Content-Type"].size() >= (unsigned)maxs) return 0;
	strcpy(bboundary, rh["Content-Type"].c_str());
	boundary = strstr(bboundary, "boundary=");
	if (!boundary) return 0;
	boundary += 9;
	if (*boundary == '\"') {
		++boundary;
		p = strchr(boundary, '\"');
		if (p) *p = 0;
		if (boundary[0] == 0) return 0;
		return boundary;
	}
	if ((p = strchr(boundary, ';')) != 0) *p = 0;
	if ((p = strchr(boundary, ' ')) != 0) *p = 0;
	if ((p = strchr(boundary, '\r')) != 0) *p = 0;
	if ((p = strchr(boundary, '\n')) != 0) *p = 0;
	if (boundary[0] == 0) return 0;
	return boundary;
}

unsigned HTTPServer::loadMultipartBuf(istream& i, char *buf, int maxl)
{
	if (i.rdbuf()->in_avail() == 0 && i.peek() == EOF) return 0;
	if (maxl > i.rdbuf()->in_avail()) maxl = i.rdbuf()->in_avail();
	i.read(buf,maxl);
	return (unsigned)maxl;
}

void HTTPServer::loadMultipart(istream& i)
{
	char bboundary[256], buf[2048], *boundary, *p, *ep, *rep, *sp;
	string name;

	boundary = parseBoundary(bboundary, 256);
	
	// following states are possible:
	// 0 - outside of any boundaries
	// 1 - inside - parsing headers
	// 2 - inside of content-disposition header - namea
	// 3 - inside of name
	// 4 - inside of content-disposition header - filename
	// 5 - inside of filename
	// 6 - inside - skipping headers
	// 7 - inside - parsing body
	
	unsigned state = 0, blen = strlen(boundary);
	bool need_data = false;

	sp = &buf[0]; rep = p = ep = &buf[2048];

	for (;;) {
		if (p == ep || need_data) {
			if (p != ep) memmove(sp,p,ep-p);
			unsigned ldl = loadMultipartBuf(i,sp+(ep-p), rep - sp - (ep-p));
			if (p == ep && ldl == 0) break; // EOF
			if (ldl == 0 && need_data) break; // EOF
			ep = sp + (ep - p) + ldl;
			p = sp;
			need_data = false;
		}

		if (state == 7) { // copy to h[name] everything before boundary
			char *p1 = (char*)memchr(p,boundary[0],ep-p);
			if (!p1) {
				h[name] += string(p,ep-p);
				p = ep;
				continue;
			}
			if (ep - p1 < blen) { need_data = true; continue; }
			if (!memcmp(p1,boundary,blen)) {
				string& str = h[name];
				str += string(p,p1-p);
				p = p1;
				if (str.size() > 1 && str[str.size()-1] == '-') str.resize(str.size()-1);
				if (str.size() > 1 && str[str.size()-1] == '-') str.resize(str.size()-1);
				if (str.size() > 1 && str[str.size()-1] == '\n') str.resize(str.size()-1);
				if (str.size() > 1 && str[str.size()-1] == '\r') str.resize(str.size()-1);
				state = 1;
				p += blen;
			} else {
				h[name] += string(p,p1-p+1);
				p = p1 + 1;
			}
		} else if (state == 0) {
			p = (char*)memchr(p,boundary[0],ep-p);
			if (!p) { p = ep; continue; }
			if ((unsigned)(ep-p) < blen) { need_data = true; continue; }
			if (!memcmp(p,boundary,blen)) {
				state = 1;
				p += blen;
				continue;
			}
			++p;
		} else if (state == 1) { // state == 1 - inside of headers
			while (p != ep && (*p == '\n' || *p == '\r')) ++p;
			if (ep - p < 27) { need_data = true; continue; }
			// locate Content-Disposition header
			if (!memcmp(p,"Content-Disposition:", 20)) {
				state = 2;
				p += 20;
			} else {
				p = (char*)memchr(p,'\n',ep-p);
				if (!p) p = ep;
				else ++p;
			}
		} else if (state == 2) { // inside of content-dispos header
			while (p != ep && (*p == ' ' || *p == '\t')) ++p;
			if (ep - p < 6) { need_data = true; continue; }
			if (!memcmp(p,"name=",5)) {
				state = 3;
				p += 5;
			} else ++p;
		} else if (state == 3) { // parsing name header
			while (p != ep && *p == ' ') ++p;
			if (p == ep) continue;
			if (*p == '\"') {
				char *p1 = (char*)memchr(p+1,'\"',ep-p-1);
				if (!p1) { need_data = true; continue; }
				name = string(p+1, p1 - p - 1);
				fn[name] = "";
				h[name] = "";
				p = p1+1;
				state = 4;
			} else {
				char *p1 = (char*)memchr(p,' ',ep-p);
				if (!p1) p1 = (char*)memchr(p,';',ep-p);
				if (!p1) p1 = (char*)memchr(p,'\r',ep-p);
				if (!p1) p1 = (char*)memchr(p,'\n',ep-p);
				if (!p1) { need_data = true; continue; }
				name = string(p, p1 - p);
				fn[name] = "";
				h[name] = "";
				p = p1;
				state = 4;
			}
		} else if (state == 4) {
			while (p != ep && *p == ' ') ++p;
			if (p == ep) continue;
			if (*p == '\r' || *p == '\n') { state = 6; continue; }
			if (ep - p < 9) { need_data = true; continue; }
			if (!memcmp(p,"filename=",9)) {
				state = 5;
				p += 9;
			} else ++p;
		} else if (state == 5) {
			while (p != ep && *p == ' ') ++p;
			if (p == ep) continue;
			if (*p == '\"') {
				char *p1 = (char*)memchr(p+1,'\"',ep-p-1);
				if (!p1) { need_data = true; continue; }
				fn[name] = string(p+1, p1 - p - 1);
				p = p1+1;
				state = 6;
			} else {
				char *p1 = (char*)memchr(p,' ',ep-p);
				if (!p1) p1 = (char*)memchr(p,';',ep-p);
				if (!p1) p1 = (char*)memchr(p,'\r',ep-p);
				if (!p1) p1 = (char*)memchr(p,'\n',ep-p);
				if (!p1) { need_data = true; continue; }
				fn[name] = string(p, p1 - p);
				p = p1;
				state = 6;
			}
		} else if (state == 6) {
			char *p1 = (char*)memchr(p,'\n',ep-p);
			if (!p1) { p = ep; continue; }
			if (ep - p1 < 3) { need_data = true; continue; }
			if (p1[1] == '\n') {
				state = 7;
				p = p1+2;
			} else if (p1[1] == '\r' && p1[2] == '\n') {
				state = 7;
				p = p1+3;
			} else p = p1+1;
		}
	}
}

void HTTPServer::loadParams()
{
	int sz;
	bool delete_i = false;
	istream *i = (istream*)0;
	if (!get_request_method && rh.find("Content-Length") != rh.end()) {
		if (rh["Content-Length"].size() <= 0) return;
		sz = atoi(rh["Content-Length"].c_str());
		if (sz <= 0 || (sz > max_request_size && max_request_size != 0))
			return;
		i = &input;
	} else {
		i = new istringstream(query_string);
		delete_i = true;
		sz = -1;
	}

	if (rh["Content-Type"].size() >= 19 && rh["Content-Type"].substr(0,19) == "multipart/form-data") {
		HTTPILimitBuf il(*i->rdbuf(), sz);
		istream ils(&il);
		loadMultipart(ils);
	} else {
		while (sz != 0 && i->peek() != EOF) {
			string n,v;
			while (sz != 0 && i->peek() != EOF && i->peek() != '=' && i->peek() != '&' && i->peek() != ';') { n += (char)i->get(); sz--; }
			if (sz ==0) break;
			if (i->peek() == '=') {
				i->get(); sz --;
				while (sz != 0 && i->peek() != EOF && i->peek() != '&' && i->peek() != ';') { v += (char)i->get(); sz--; }
			}
			if (n.size() > 0) h[urlunescape(n)] = urlunescape(v);
			if (sz == 0) break;
			if (i->peek() == '&' || i->peek() == ';') { i->get(); sz--; }
		}
	}

	if (delete_i) delete i;
}

void HTTPServer::checkLastModified()
{
	char st[64];
	th["Last-Modified"] = last_modified.formatHTTP();
	snprintf(st,63,"\"%06x-%04x-%08x\"",(last_modified.seconds() ^ 0x89c3f76e)&0xffffff,(last_modified.seconds() ^ 0x5ef1c36e)&0xffff,(last_modified.seconds() ^ 0x87d35e6c));
	th["Etag"] = st;

	if (rh.find("If-Modified-Since") != rh.end()) {
		Time t; t.parseHTTP(rh["If-Modified-Since"].c_str());
		if (last_modified < t && t.seconds() != 0) {
			block_content = true;
			head_only = true;
			status = 304;
		}
	} else if (rh.find("If-Unmodified-Since") != rh.end()) {
		Time t; t.parseHTTP(rh["If-Unmodified-Since"].c_str());
		if (last_modified > t && t.seconds() != 0) {
			block_content = true;
			head_only = true;
			status = 412;
		}
	} else if (rh.find("If-Match") != rh.end()) {
		const string& s(rh["If-Match"]);
		if (s.find(th["Etag"]) >= s.size() && s.find('*') >= s.size()) {
			block_content = true;
			head_only = true;
			status = 412;
		}
	} else if (rh.find("If-None-Match") != rh.end()) {
		const string& s(rh["If-None-Match"]);
		if (s.find(th["Etag"]) < s.size()) {
			block_content = true;
			head_only = true;
			status = 304;
		}
	}
}

void HTTPServer::beginData()
{
	th["Server"] = "Apache";
	block_content = false;
	if (!status) status = 200;
	if (status == 200 && last_modified.seconds() != 0) {
		checkLastModified();
	}
	Time t; t.now();
	th["Date"] = t.formatHTTP();
	if (rh["Connection"] == "close" && !is_10) th["Connection"] = "close";
	if (th.find("Content-Type") == th.end()) th["Content-Type"]="text/html";

	if (tcp) {
		if (is_10) real_output << "HTTP/1.0 " << status;
		else real_output << "HTTP/1.1 " << status;
		switch (status) {
		case 100: real_output << " Continue\r\n"; break;
		case 101: real_output << " Switching protocols\r\n"; break;
		case 200: real_output << " OK\r\n"; break;
		case 201: real_output << " Created\r\n"; break;
		case 202: real_output << " Accepted\r\n"; break;
		case 203: real_output << " Non-Authorative Information\r\n"; break;
		case 204: real_output << " No Content\r\n"; break;
		case 205: real_output << " Reset Content\r\n"; break;
		case 206: real_output << " Partial Content\r\n"; break;
		case 300: real_output << " Multiple Choices\r\n"; break;
		case 301: real_output << " Moved Permanently\r\n"; break;
		case 302: real_output << " Found\r\n"; break;
		case 303: real_output << " See Other\r\n"; break;
		case 304: real_output << " Not Modified\r\n"; break;
		case 305: real_output << " Use Proxy\r\n"; break;
		case 307: real_output << " Temporary Redirect\r\n"; break;
		case 400: real_output << " Bad Request\r\n"; break;
		case 401: real_output << " Unauthorized\r\n"; break;
		case 402: real_output << " Payment Required\r\n"; break;
		case 403: real_output << " Forbidden\r\n"; break;
		case 404: real_output << " Not Found\r\n"; break;
		case 405: real_output << " Method Not Allowed\r\n"; break;
		case 406: real_output << " Not Acceptable\r\n"; break;
		case 407: real_output << " Proxy Authentication Required\r\n"; break;
		case 408: real_output << " Request Timeout\r\n"; break;
		case 409: real_output << " Conflict\r\n"; break;
		case 410: real_output << " Gone\r\n"; break;
		case 411: real_output << " Length Required\r\n"; break;
		case 412: real_output << " Precondition Failed\r\n"; break;
		case 413: real_output << " Request Entity Too Large\r\n"; break;
		case 414: real_output << " Request-URI Too Long\r\n"; break;
		case 415: real_output << " Unsupported Media Type\r\n"; break;
		case 416: real_output << " Requested Range Not Satisfiable\r\n"; break;
		case 417: real_output << " Expectation Failed\r\n"; break;
		case 500: real_output << " Internal Server Error\r\n"; break;
		case 501: real_output << " Not Implemented\r\n"; break;
		case 502: real_output << " Bad Gateway\r\n"; break;
		case 503: real_output << " Service Unavailable\r\n"; break;
		case 504: real_output << " Gateway Timeout\r\n"; break;
		case 505: real_output << " HTTP Version Not Supported\r\n"; break;
		default: real_output << "\r\n"; break;
		}

	} else if (status && status != 200) {
		real_output << "Status: " << status << "\r\n";
	}

	bool nochunk = false;

	if (block_content) nochunk = true;
	if (th.find("Content-Length") != th.end()) nochunk = true;
	if (rh.find("no-chunked-encoding") != rh.end()) nochunk = true;
	if (th["Content-Type"].size() >= 4 && th["Content-Type"].substr(0,4) != "text") nochunk = true;
	if (rh["Connection"] != "close") nochunk = true;
	
	if (!is_10 && tcp && !nochunk) th["Transfer-Encoding"] = "chunked";

	if (!block_content) {
		for (HTTPCookies::const_iterator ci = c.begin(); ci != c.end(); ci++)
			if (ci->second.getDomain().size() > 0)
				real_output << "Set-Cookie: " << c.getCookie(ci,server_name) << "\r\n";
	}

	if (block_content) { // eliminate all Content-related headers
		map<string,string,HTTPHeaderStringCmp>::iterator ti;
		ti = th.find("Content-Type");
		if (ti != th.end()) th.erase(ti);
		ti = th.find("Content-Length");
		if (ti != th.end()) th.erase(ti);
		ti = th.find("Content-Encoding");
		if (ti != th.end()) th.erase(ti);
		ti = th.find("Last-Modified");
		if (ti != th.end()) th.erase(ti);
		ti = th.find("Pragma");
		if (ti != th.end()) th.erase(ti);
		ti = th.find("Cache-Control");
		if (ti != th.end()) th.erase(ti);
		ti = th.find("Expires");
		if (ti != th.end()) th.erase(ti);
		ti = th.find("Etag");
		if (ti != th.end()) th.erase(ti);
	}

	for (map<string,string,HTTPHeaderStringCmp>::iterator ti = th.begin(); ti != th.end(); ti++)
		if (ti->second.size() > 0) real_output << ti->first << ": " << ti->second << "\r\n";

	if (!head_only) {
		if (!is_10 && tcp && !nochunk) {
			real_output << "\r\n";
			chunkbuf = new HTTPOChunkedBuf(*real_output.rdbuf());
			if (!chunkbuf) { status = -1; return; }
			rdbuf(chunkbuf);
		} else if (!tcp && !nochunk) {
			real_output << "\r\n";
			rdbuf(real_output.rdbuf());
		} else if (th.find("Content-Length") == th.end()) {
			strbuf = new strstreambuf();
			if (!strbuf) { status = -1; return; }
			rdbuf(strbuf);
		} else { real_output << "\r\n"; rdbuf(real_output.rdbuf()); }

	} else {
		strbuf = new strstreambuf();
		if (!strbuf) { status = -1; return; }
		rdbuf(strbuf);
	}
}

HTTPServer::HTTPServer(int maxr) : ostream(0), input(cin), real_output(cout)
{
	max_request_size = maxr;
	rdbuf(real_output.rdbuf());
	tcp = (TCPStream*)0;
	chunkbuf = (HTTPOChunkedBuf*)0;
	strbuf = 0;
	is_10 = head_only = false; get_request_method = true;
	status = 0;
	
	char *s = getenv("REMOTE_USER");
	if (s) remote_user = s;

	s = getenv("HTTP_USER_AGENT");
	if (s) rh["User-Agent"] = s;

	s = getenv("REQUEST_METHOD");
	if (s && (s[0] == 'P' || s[0] == 'p')) get_request_method = false;

	s = getenv("SERVER_NAME");
	if (s) server_name = s;

	s = getenv("SERVER_PORT");
	if (s) server_port = atoi(s); else server_port = 80;

	s = getenv("SCRIPT_NAME");
	if (s) path = s;
	
	s = getenv("PATH_INFO");
	if (s) path += s;

	s = getenv("HTTP_REFERER");
	if (s) rh["Referer"] = s;

	s = getenv("REMOTE_ADDR");
	if (s) peer_address.set(s);

	s = getenv("REMOTE_PORT");
	if (s) peer_address.setPort(atoi(s));

	s = getenv("HTTP_COOKIE");
	if (s) c.loadCookies(s);

	s = getenv("CONTENT_TYPE");
	if (s) rh["Content-Type"] = s;

	s = getenv("CONTENT_LENGTH");
	if (s) rh["Content-Length"] = s;

	s = getenv("QUERY_STRING");
	if (s) query_string = s;

	s = getenv("HTTP_ACCEPT_ENCODING");
	if (s) rh["Accept-Encoding"] = s;

	s = getenv("HTTP_ACCEPT");
	if (s) rh["Accept"] = s;

	s = getenv("HTTP_ACCEPT_LANGUAGE");
	if (s) rh["Accept-Language"] = s;

	loadParams();
}

HTTPServer::HTTPServer(TCPStream* sock) : ostream(0), tcp(sock), input(*tcp), real_output(*tcp)
{
	if (!tcp) { status = -1; return; }
	rdbuf(tcp);
	chunkbuf = (HTTPOChunkedBuf*)0;
	strbuf = 0;
	is_10 = head_only = false; get_request_method = true;
	status = 0;
}

HTTPServer::HTTPServer(TCPSocket& sock) : ostream(0), tcp(new TCPStream(sock,peer_address)), input(*tcp), real_output(*tcp)
{
	if (!tcp) { status = -1; return; }
	rdbuf(tcp);
	chunkbuf = (HTTPOChunkedBuf*)0;
	strbuf = 0;
	is_10 = head_only = false; get_request_method = true;
	status = 0;
}

HTTPServer::HTTPServer(TCPSocket& sock, const char *certname, const char *keyname) : ostream(0), tcp(new TCPSSLStream(sock,peer_address,certname,keyname)), input(*tcp), real_output(*tcp)
{
	if (!tcp) { status = -1; return; }
	rdbuf(tcp);
	chunkbuf = (HTTPOChunkedBuf*)0;
	strbuf = 0;
	is_10 = head_only = false; get_request_method = true;
	status = 0;
}

HTTPServer::HTTPServer(TCPStream* tcps, const string& sname, int sport, int maxr) : ostream(0), tcp(tcps), input(*tcp), real_output(*tcp)
{
	if (!tcp) { status = -1; return; }
	accept(sname,sport,maxr);
}

HTTPServer::HTTPServer(TCPStream* tcps, const string& sname,  const char *certname, const char *keyname, int sport, int maxr) : ostream(0), tcp(tcps), input(*tcp), real_output(*tcp)
{
	if (!tcp) { status = -1; return; }
	accept(sname,sport,maxr);
}


HTTPServer::HTTPServer(TCPSocket& sock, const string& sname, int sport, int maxr) : ostream(0), tcp(new TCPStream(sock,peer_address)), input(*tcp), real_output(*tcp)
{
	if (!tcp) { status = -1; return; }
	accept(sname,sport,maxr);
}

HTTPServer::HTTPServer(TCPSocket& sock, const string& sname,  const char *certname, const char *keyname, int sport, int maxr) : ostream(0), tcp(new TCPSSLStream(sock,peer_address,certname,keyname)), input(*tcp), real_output(*tcp)
{
	if (!tcp) { status = -1; return; }
	accept(sname,sport,maxr);
}

void HTTPServer::accept(const string& sname, int sport, int maxr)
{
	if (!tcp) return;
	do_shutdown = false;
	rdbuf(tcp);
	max_request_size = maxr;
	server_name = sname;
	server_port = sport;
	chunkbuf = (HTTPOChunkedBuf*)0;
	strbuf = 0;
	is_10 = head_only = false; get_request_method = true;
	status = 0;
	rh.clear();
	th.clear();
	path.resize(0);
	remote_user.resize(0);
	query_string.resize(0);
	server_name.resize(0);
	c.clear();
	h.clear();
	fn.clear();

	int c = input.get();
	while (c == '\n' || c == '\r') c = input.get();
	if (c == 'P' || c == 'p') get_request_method = false;
	if (c == 'H' || c == 'h') head_only=true;
	while (input.peek() != EOF && input.peek() != ' ' && input.peek() != '\t' && input.peek() != '\n' && input.peek() != '\r') input.get();
	while (input.peek() == ' ' || input.peek() == '\t') input.get();

	int psz = 0;
	if (input.peek() != '/') path = "/"; // by default '/' added
	if (input.peek() == 'H' || input.peek() == 'h') {
		path += (char)input.get();
		if (input.peek() == 'T' || input.peek() == 't') { path += (char)input.get();
		if (input.peek() == 'T' || input.peek() == 't') { path += (char)input.get();
		if (input.peek() == 'P' || input.peek() == 'p') { path += (char)input.get();
		if (input.peek() == 'S' || input.peek() == 's') path += (char)input.get();
		if (input.peek() == ':') { path += (char)input.get();
		if (input.peek() == '/') { path += (char)input.get();
		if (input.peek() == '/') { input.get(); path.resize(0);
			while (input.peek() != EOF && input.peek() != ' ' && input.peek() != '\t' && input.peek() != '\n' && input.peek() != '\r' && input.peek() != '?' && input.peek() != '/') input.get();
		} } } } } }
	}

	while (input.peek() != EOF && input.peek() != ' ' && input.peek() != '\t' && input.peek() != '\n' && input.peek() != '\r' && input.peek() != '?') { path += (char)input.get(); psz++; if (psz >= 1024) { status = -1; return; } }

	if (input.peek() == '?') {
		int qsz_size = 0;
		input.get();
		while (input.peek() != EOF && input.peek() != ' ' && input.peek() != '\t' && input.peek() != '\n' && input.peek() != '\r') { query_string += (char)input.get(); qsz_size++; if (qsz_size >= 1024) { status = -1; return; } }
	}
	while (input.peek() == ' ' || input.peek() == '\t') input.get();
	c = input.get(); if (c != 'H' && c != 'h') { status = -1; return; }
	c = input.get(); if (c != 'T' && c != 't') { status = -1; return; }
	c = input.get(); if (c != 'T' && c != 't') { status = -1; return; }
	c = input.get(); if (c != 'P' && c != 'p') { status = -1; return; }
	if (input.get() != '/') { status = -1; return; }
	if (input.get() != '1') { status = -1; return; }
	if (input.get() != '.') { status = -1; return; }

	if (input.get() == '0') is_10 = true;

	psz = 0;
	do {
		string n, v;
		while (input.peek() != EOF && input.peek() != ':' && input.peek() != '\n' && input.peek() != '\r') {
			n += (char)input.get();
			psz++;
			if (psz >= 8192) { status = -1; return; }
		}
		if (input.peek() == ':') {
			while (input.peek() == ':' || input.peek() == ' ' || input.peek() == '\t') input.get();
			while (input.peek() != EOF && input.peek() != '\n' && input.peek() != '\r') {
				v += (char)input.get();
				psz ++;
				if (psz >= 8192) { status = -1; return; }
			}
			rh[n] = v;
		}
		if (input.peek() == '\r') input.get();
		if (input.peek() == '\n') input.get();
		if (input.peek() == '\r' || input.peek() == '\n') break;
	} while (input.peek() != EOF && input.peek() != '\n' && input.peek() != '\r');
	if (input.peek() == '\r') input.get();
	if (input.peek() == '\n') input.get();
	HTTPServer::c.clear();
	if (rh.find("Cookie") != rh.end()) HTTPServer::c.loadCookies(rh["Cookie"].c_str());
	loadParams();
	if (is_10 && rh["Connection"] != "keep-alive" && rh["Connection"] != "Keep-Alive") setClose();
	else if (rh["Connection"] == "Keep-Alive") th["Connection"] = "Keep-Alive";
	else if (rh["Connection"] == "keep-alive") th["Connection"] = "keep-alive";
}

HTTPServer::~HTTPServer()
{
	setClose();
	endRequest();
}

string HTTPServer::getDirURL(bool https)
{
	string s;
	if (https) s += "https://"; else s += "http://";
	if (rh.find("Host") != rh.end()) s += rh["Host"];
	else s += server_name;
	if ((https && server_port != 443) || (!https && server_port != 80)) {
		char prt[16];
		snprintf(prt,15,":%d",server_port);
		s += prt;
	}

	return s;
}

string HTTPServer::getBaseURL(bool https)
{
	return getDirURL(https) + path;
}

string HTTPServer::getFullURL(bool https)
{
	if (query_string.size() > 0) return getBaseURL(https) + "?" + query_string;
	return getBaseURL(https);
}

void HTTPServer::fullflush()
{
	if (!chunkbuf) return;
	flush();
	real_output.flush();
}
	
void HTTPServer::endRequest()
{
	if (!rdbuf((streambuf*)0)) return;
	if (strbuf) {
		if (!head_only) {
			real_output << "Content-Length: " << ((strstreambuf*)strbuf)->pcount() << "\r\n\r\n";
			if (((strstreambuf*)strbuf)->pcount() > 0) {
				real_output.write(((strstreambuf*)strbuf)->str(),((strstreambuf*)strbuf)->pcount());
				((strstreambuf*)strbuf)->freeze(false);
			}
		} else {
			if (!block_content && th.find("Content-Length") == th.end())
				real_output << "Content-Length: " << ((strstreambuf*)strbuf)->pcount() << "\r\n\r\n";
		}
		delete (strstreambuf*)strbuf;
		strbuf = 0;
			
	}
	if (chunkbuf) { delete chunkbuf; chunkbuf = (HTTPOChunkedBuf*)0; }
	real_output.flush();
	if ((th["Connection"] == "close" || rh["Connection"] == "close") && tcp) { if (do_shutdown) tcp->shutdown(); delete tcp; tcp = (TCPStream*)0; }
	if (tcp) rdbuf(tcp);
}

static char urlhex[] = {"0123456789ABCDEF"};

static inline char urldehex(char c)
{
	switch (c) {
	case '0': return 0;
	case '1': return 1;
	case '2': return 2;
	case '3': return 3;
	case '4': return 4;
	case '5': return 5;
	case '6': return 6;
	case '7': return 7;
	case '8': return 8;
	case '9': return 9;
	case 'a': return 10;
	case 'b': return 11;
	case 'c': return 12;
	case 'd': return 13;
	case 'e': return 14;
	case 'f': return 15;
	case 'A': return 10;
	case 'B': return 11;
	case 'C': return 12;
	case 'D': return 13;
	case 'E': return 14;
	case 'F': return 15;
	}
	return 0;
}

string urlescape(const string& s)
{
	string out;
	string::const_iterator i;

	out.resize(s.size()*3);
	string::iterator o = out.begin();

	for (i = s.begin(); i != s.end(); i++) {
		if ((*i >= '0' && *i <= '9') || (*i >= 'A' && *i <= 'Z') || (*i >= 'a' && *i <= 'z') || *i == '_' || *i == '-' || *i == '.' || *i == '@' || *i == '$') { *o++ = *i; continue; }
		if (*i == ' ') { *o++ = '+'; continue; }
		*o++ = '%';
		char c = *i;
		*o++ = urlhex[(c >> 4) & 0x0f];
		*o++ = urlhex[c & 0x0f];
	}
	
	out.resize(o-out.begin());

	return out;
}

string urlunescape(const string& s)
{
	string::const_iterator i;
	string out;

	out.resize(s.size());
	string::iterator o = out.begin();

	for (i = s.begin(); i != s.end(); i++) {
		if (*i == '%') {
			char c;
			i++; if (i == s.end()) break; c = urldehex(*i) << 4;
			i++; if (i == s.end()) break; c |= urldehex(*i);
			*o++ = c;
			continue;
		}
		if (*i == '+') { *o++ = ' '; continue; }
		*o++ = *i;
	}
	
	out.resize(o-out.begin());

	return out;
}

string htmlize(const string& s)
{
	string out;
	const char *sp = s.c_str();
	const char *p = strpbrk(sp,"&\"<>");

	while (p && *p) {
		if (p != sp) out.append(sp,p-sp);
		if (*p == '&') {
			out.append("&amp;");
		} else if (*p == '\"') {
			out.append("&quot;");
		} else if (*p == '<') {
			out.append("&lt;");
		} else if (*p == '>') {
			out.append("&gt;");
		}
		sp = p+1;
		p = strpbrk(sp,"&\"<>");
	}
	if (sp && *sp) out.append(sp);

//	for (string::const_iterator i = s.begin(); i != s.end(); i++)
//		switch (*i) {
//		case '&': out.append("&amp;"); break;
//		case '\"': out.append("&quot;"); break;
//		case '<': out.append("&lt;"); break;
//		case '>': out.append("&gt;"); break;
//		default: out += *i; break;
//		}

	return out;
}

};

#ifndef SOL_IP
#define SOL_IP IPPROTO_IP
#endif

using namespace std;

namespace handylib {

static unsigned TCPStream_written = 0, TCPStream_read = 0, TCPStream_accept = 0, TCPStream_connect;

static void sock_nonblock(int so)
{
	int flags = fcntl(so,F_GETFL,0);
	flags |= O_NONBLOCK;
	fcntl(so,F_SETFL,flags);
}

SocketAddress::~SocketAddress() { }

UnixAddress::~UnixAddress() { }

void UnixAddress::setAddress(const void *addr, int addr_len)
{
	if (!addr || addr_len < 4) return;
	struct sockaddr_un *u;
	u = (struct sockaddr_un *)addr;
	if (u->sun_family != AF_UNIX) return;
	path = u->sun_path;
}

int UnixAddress::getAddress(void *addr, int addr_maxlen) const
{
	if (!addr || sizeof(struct sockaddr_un) > (unsigned)addr_maxlen) return 0;
	struct sockaddr_un *u = (struct sockaddr_un*)addr;
	memset(u,0,addr_maxlen);
	u->sun_family = AF_UNIX;
	strncpy(u->sun_path,path.c_str(),100);
	return sizeof(struct sockaddr_un);
}

IPAddress::~IPAddress() { }

void IPAddress::setAddress(const void *addr, int addr_len)
{
	if (!addr) return;
	struct sockaddr_in *i = (struct sockaddr_in*)addr;
	if (i->sin_family != AF_INET) return;
	port = ntohs(i->sin_port);
	ip = n2h(i->sin_addr.s_addr);
}

int IPAddress::getAddress(void *addr, int addr_maxlen) const
{
	if (!addr || sizeof(struct sockaddr_in) > (unsigned)addr_maxlen) return 0;
	struct sockaddr_in *i = (struct sockaddr_in*)addr;
	memset(i,0,addr_maxlen);
#ifdef __FreeBSD__
	i->sin_len = sizeof(struct sockaddr_in);
#endif
	i->sin_family = AF_INET;
	i->sin_port = htons(port);
	i->sin_addr.s_addr = h2n(ip);
	return sizeof(struct sockaddr_in);
}

string IPAddress::getString(bool needport) const
{
	unsigned a,b,c,d;

	a = (ip & 0xff000000) >> 24;
	b = (ip & 0x00ff0000) >> 16;
	c = (ip & 0x0000ff00) >> 8;
	d = (ip & 0x000000ff);

	string s;
	s.resize(32);
	if (!needport)
		snprintf((char*)s.data(),30,"%d.%d.%d.%d",a,b,c,d);
	else
		snprintf((char*)s.data(),30,"%d.%d.%d.%d:%d",a,b,c,d,port);
	s.resize(strlen(s.c_str()));
	return s;
}

string IPAddress::getRevString() const
{
	unsigned a,b,c,d;

	d = (ip & 0xff000000) >> 24;
	c = (ip & 0x00ff0000) >> 16;
	b = (ip & 0x0000ff00) >> 8;
	a = (ip & 0x000000ff);

	string s;
	s.resize(18);
	snprintf((char*)s.data(),16,"%d.%d.%d.%d",a,b,c,d);
	s.resize(strlen(s.c_str()));
	return s;
}

bool IPAddress::set(const string& s, const string& p)
{
	unsigned a,b,c,d;
	bool ret = true;
	port = 0;
	if (sscanf(s.c_str(),"%u.%u.%u.%u",&d,&c,&b,&a) < 4) ret = false;
	sscanf(p.c_str(),"%u",&port);
	ip = ((d & 0xff) << 24) | ((c & 0xff) << 16) | ((b & 0xff) << 8) |
	      (a & 0xff);
	return ret;
}

bool IPAddress::set(const char *s)
{
	unsigned a,b,c,d;
	bool ret = true;

	port = 0;
	if (sscanf(s,"%u.%u.%u.%u:%u",&d,&c,&b,&a,&port) < 4) {
		a = 0;
		if (sscanf(s,"%u.%u.%u:%u",&d,&c,&b,&port) < 3) {
			b = 0;
			if (sscanf(s,"%u.%u:%u",&d,&c,&port) < 2) {
				c = 0;
				if (sscanf(s,"%u:%u",&d,&port) < 1) {
					ret = false;
					d = 0;
				}
			}
		}
	}
	ip = ((d & 0xff) << 24) | ((c & 0xff) << 16) | ((b & 0xff) << 8) |
	      (a & 0xff);
	return ret;
}

unsigned long IPAddress::h2n(unsigned long x) { return htonl(x); }
unsigned long IPAddress::n2h(unsigned long x) { return ntohl(x); }

void Socket::setZeroLinger()
{
	if (so < 0) return;
	struct linger l;
	l.l_onoff = 1;
	l.l_linger = 0;
	setsockopt(so,SOL_SOCKET,SO_LINGER,(void*)&l,sizeof(l));
}

void Socket::shutdown(int dir)
{
	if (so < 0) return;
	if (dir == 1) ::shutdown(so,SHUT_RD);
	else if (dir == 2) ::shutdown(so,SHUT_WR);
	else {
		setZeroLinger();
		::shutdown(so,SHUT_RDWR);
		::close(so);
		so = -1;
	}
}

void Socket::close()
{
	if (so >= 0) { ::close(so); so = -1; }
}

Socket::~Socket()
{
	if (so >= 0) { ::close(so); so = -1; }
}

Socket::Socket()
{
	err = Socket::OK;
	so = -1;
	flags = 0;
//#ifdef MSG_NOSIGNAL
//	flags = MSG_NOSIGNAL | MSG_DONTWAIT;
//#else
//	flags = MSG_DONTWAIT;
//#endif
	to = 300000;
}

void Socket::setOOBInline(bool oobinline)
{
	int k = oobinline;
	setsockopt(so,SOL_SOCKET,SO_OOBINLINE,&k,sizeof(k));
}

bool Socket::getOOBInline()
{
	int k = 0; socklen_t ks = sizeof(int);
	getsockopt(so,SOL_SOCKET,SO_OOBINLINE,&k,&ks);
	return k;
}

void Socket::setReuseAddr(bool reuse)
{
	int k = reuse;
	setsockopt(so,SOL_SOCKET,SO_REUSEADDR,&k,sizeof(k));
}

bool Socket::getReuseAddr()
{
	int k = 0; socklen_t ks = sizeof(int);
	getsockopt(so,SOL_SOCKET,SO_REUSEADDR,&k,&ks);
	return k;
}

void Socket::bindToDevice(const char *dev)
{
#ifdef SO_BINDTODEVICE
	setsockopt(so,SOL_SOCKET,SO_BINDTODEVICE,dev,strlen(dev));
#endif
}

void Socket::setDontRoute(bool dontroute)
{
	int k = dontroute;
	setsockopt(so,SOL_SOCKET,SO_DONTROUTE,&k,sizeof(k));
}

bool Socket::getDontRoute()
{
	int k = 0; socklen_t ks = sizeof(int);
	getsockopt(so,SOL_SOCKET,SO_DONTROUTE,&k,&ks);
	return k;
}

void Socket::setBroadcast(bool broadcast)
{
	int k = broadcast;
	setsockopt(so,SOL_SOCKET,SO_BROADCAST,&k,sizeof(k));
}

bool Socket::getBroadcast()
{
	int k = 0; socklen_t ks = sizeof(int);
	getsockopt(so,SOL_SOCKET,SO_BROADCAST,&k,&ks);
	return k;
}

void Socket::setSendBufferSize(int sndbuf)
{
	setsockopt(so,SOL_SOCKET,SO_SNDBUF,&sndbuf,sizeof(sndbuf));
}

int Socket::getSendBufferSize()
{
	int k = 0; socklen_t ks = sizeof(int);
	getsockopt(so,SOL_SOCKET,SO_SNDBUF,&k,&ks);
	return k;
}

void Socket::setRecvBufferSize(int rcvbuf)
{
	setsockopt(so,SOL_SOCKET,SO_RCVBUF,&rcvbuf,sizeof(rcvbuf));
}

int Socket::getRecvBufferSize()
{
	int k = 0; socklen_t ks = sizeof(int);
	getsockopt(so,SOL_SOCKET,SO_RCVBUF,&k,&ks);
	return k;
}

void Socket::setOOB(bool oob)
{
	if (oob) flags |= MSG_OOB;
	else flags &= ~MSG_OOB;
}

bool Socket::getOOB() { return flags & MSG_OOB; }

int Socket::sendto(const void *msg, unsigned len, const SocketAddress& t)
{
	char addr[128];
	int sza = t.getAddress(addr,128), sz;
	for (;;) {
		sz = ::sendto(so,msg,len,flags,(struct sockaddr*) addr,sza);
		if (sz < 0)
			switch (errno) {
			case EMSGSIZE: return 0;
			case EWOULDBLOCK:
				if (!threads_waitonfd(so,WAIT_WRITE,to)) {
					err = Socket::TimedOut;
					return 0;
				}
				continue;
			case EINTR: continue;
			case EPIPE: err = Socket::NotConnected; return 0;
			default: err = Socket::FatalError; return 0;
			}
			
		return sz;
	}
}

int Socket::recvfrom(void *buf, unsigned len, SocketAddress& from)
{
	char addr[128];
	int sz; socklen_t sza = 128;
	for (;;) {
		sz = ::recvfrom(so,buf,len,flags,(struct sockaddr*) addr,&sza);
		if (sz < 0)
			switch (errno) {
			case EWOULDBLOCK:
				if (!threads_waitonfd(so,WAIT_READ,to)) {
					err = Socket::TimedOut;
					return 0;
				}
				continue;
			case EINTR: continue;
			case ECONNREFUSED: err = Socket::ConnectionRefused; return 0;
			case ENOTCONN: case EPIPE: err = Socket::NotConnected; return 0;
			default: err = Socket::FatalError; return 0;
			}
		from.setAddress(addr,sza);
		return sz;
	}
}

void Socket::bind(const SocketAddress& addr)
{
	char a[128];
	int sza = addr.getAddress(a,128);
	if (::bind(so,(struct sockaddr*)a,sza) < 0) { switch (errno) {
	case EACCES:
	case EADDRNOTAVAIL:case EADDRINUSE: err = Socket::AddressInUse; return;
	default: err = Socket::FatalError; return;
	} }
}

bool StreamSocket::waitForData(unsigned msec)
{
	if (in_avail() > 0) return true;
	return threads_waitonfd(so,WAIT_READ, msec);
}

void StreamSocket::setKeepAlive(bool keepalive)
{
	int k = keepalive;
	setsockopt(so,SOL_SOCKET,SO_KEEPALIVE,&k,sizeof(k));
}

bool StreamSocket::getKeepAlive()
{
	int k = 0; socklen_t ks = sizeof(int);
	getsockopt(so,SOL_SOCKET,SO_KEEPALIVE,&k,&ks);
	return k;
}

void StreamSocket::connect(const SocketAddress& a)
{
	char addr[128];
	int sza = a.getAddress(addr,128);
	setReuseAddr();
	for (;;) {
		if (::connect(so,(struct sockaddr*) addr,sza)< 0) switch(errno) {
		case EAGAIN: threads_sleep(1000);
		case EALREADY: case EINPROGRESS:
			if (!threads_waitonfd(so,WAIT_WRITE|WAIT_READ,to)) {
				err = Socket::TimedOut;
				return;
			}
			continue;
		case EADDRINUSE: err = Socket::AddressInUse; return;
		case ECONNREFUSED: err = Socket::ConnectionRefused; return;
		case EISCONN: EmergeBuffers(); TCPStream_connect++; return;
		case ENETUNREACH: err = Socket::Unreachable; return;
		case EINTR: continue;
		default: err = Socket::FatalError; return;
		}
		break;
	}
	EmergeBuffers();
	TCPStream_connect++;
}

int StreamSocket::send(const void *msg, unsigned len)
{
	for (;;) {
		int sz = ::send(so,msg,len,Socket::flags);
		if (sz < 0)
			switch (errno) {
			case EMSGSIZE: return 0;
			case EWOULDBLOCK:
				if (!threads_waitonfd(so,WAIT_WRITE,to)) {
					err = Socket::TimedOut;
					return 0;
				}
				continue;
			case EINTR: continue;
			case EPIPE: err = Socket::NotConnected; return 0;
			default: err = Socket::FatalError; return 0;
			}
		
		TCPStream_written += sz;
		return sz;
	}
}

int StreamSocket::recv(void *buf, size_t len)
{
	for (;;) {
		int sz = ::recv(so,buf,len,Socket::flags);
		if (sz < 0)
			switch (errno) {
			case EWOULDBLOCK:
				if (!threads_waitonfd(so,WAIT_READ,to)) {
					err = Socket::TimedOut;
					return 0;
				}
				continue;
			case EINTR: continue;
			case ECONNREFUSED: err = Socket::ConnectionRefused; return 0;
			case ENOTCONN: case EPIPE: err = Socket::NotConnected; return 0;
			default: err = Socket::FatalError; return 0;
			}
		TCPStream_read += sz;
		return sz;
	}
}

int StreamSocket::underflow()
{
	if (err != Socket::OK || !eback()) return EOF;
	if (gptr() < egptr())
		return (unsigned char)*gptr();

	int rlen = (gbuf+bufsize) - eback();
	rlen = recv(eback(),rlen);
	if (err != Socket::OK) return EOF;

	if (rlen < 1)
		return EOF;

	gpos += egptr() - eback();
	setg(eback(),eback(),eback()+rlen);

	return (unsigned char)*gptr();
}

int StreamSocket::sync()
{
	return overflow(EOF);
}

int StreamSocket::overflow(int ch)
{
	if (err != Socket::OK || !pbase()) { setp(pbase(),epptr()); return 0; }
	streamsize len = pptr() - pbase();
	if (len == 0 && ch == EOF) return 0;
	if (ch != EOF) { *pptr() = ch; len ++; }
	int cur = 0;
	setp(pbase(),epptr());
	while (len > 0) {
		int wsz = 0;
		wsz = send(pbase()+cur,len);
		if (err != Socket::OK) return 0;
		cur += wsz;
		ppos += wsz;
		len -= wsz;
		if (wsz == 0) return 0;
	}

	return 0;
}

void StreamSocket::DropBuffers()
{
	if (gbuf) { delete[] gbuf; gbuf = (char*)0; }
	if (pbuf) { delete[] pbuf; pbuf = (char*)0; }
}

void StreamSocket::EmergeBuffers()
{
	if (bufsize < 1) bufsize = 1;
	if (gbuf) return;
	gbuf = new char [bufsize];
	if (!gbuf) { close(); err = Socket::FatalError; setg(0,0,0); setp(0,0); return; }
	pbuf = new char [bufsize+1];
	if (!pbuf) { close(); delete [] gbuf; gbuf = (char*)0; err = Socket::FatalError; setg(0,0,0); setp(0,0); return; }
	setg(gbuf,gbuf,gbuf);
	setp(pbuf,pbuf+bufsize);
}

StreamSocket::StreamSocket(int size) : streambuf(), iostream((streambuf*)this)
{
	gbuf = pbuf = (char*)0;
	gpos = ppos = 0;
	if (size <= 0) bufsize = 1; else bufsize = size;
}

StreamSocket::~StreamSocket()
{
	sync();
	DropBuffers();
}

StreamServerSocket::~StreamServerSocket() { }

void StreamServerSocket::accept(StreamSocket& sock, SocketAddress& addr)
{
	struct sockaddr a;
	socklen_t sza;
	int errc = 0, s = 0;

	for (;;) {
		sza = sizeof(struct sockaddr);
		if ((s = ::accept(so,&a,&sza)) < 0) switch (errno) {
		case EWOULDBLOCK:
			if (!threads_waitonfd(so,WAIT_READ|WAIT_WRITE,to)) {
				err = Socket::TimedOut;
				return;
			}
			continue;
		case EPERM: err = Socket::ConnectionRefused; return;
		case EINTR: continue;
		case ENOBUFS: case ECONNABORTED:
			threads_sleep(1000);
			if (++errc == 1) continue;
		default: err = Socket::FatalError; return;
		}
		sock.so = s;
		sock_nonblock(sock.so);
		addr.setAddress(&a,sza);
		TCPStream_accept++;
		return;
	}
}

void StreamServerSocket::accept(StreamSocket& sock)
{
	int errc = 0, s = 0;


	for (;;) {
		if ((s = ::accept(so,(struct sockaddr *)0,(socklen_t*)0)) < 0) switch (errno) {
		case EWOULDBLOCK:
			if (!threads_waitonfd(so,WAIT_READ|WAIT_WRITE,to)) {
				err = Socket::TimedOut;
				return;
			}
			continue;
		case EPERM: err = Socket::ConnectionRefused; return;
		case EINTR: continue;
		case ENOBUFS: case ECONNABORTED:
			threads_sleep(1000);
			if (++errc == 1) continue;
		default: err = Socket::FatalError; return;
		}
		sock.so = s;
		sock_nonblock(sock.so);
		TCPStream_accept++;
		return;
	}
}
	
void StreamServerSocket::prepare(const SocketAddress& addr, int backlog)
{
	setReuseAddr();
	bind(addr);
	int flags = fcntl(so,F_GETFL,0);
	flags |= O_NDELAY;
	fcntl(so,F_SETFL,flags);
	if (listen(so,backlog) < 0) {
		err = Socket::FatalError;
		return;
	}
	to = 86400000;
}

StreamServerSocket::StreamServerSocket() { }

IPSocket::IPSocket() { }
IPSocket::~IPSocket() { }

void IPSocket::setRecvTOS(bool tos)
{
#ifdef IP_RECVTOS
	int k = tos;
	setsockopt(so,SOL_IP,IP_RECVTOS,&k,sizeof(int));
#endif
}

bool IPSocket::getRecvTOS()
{
#ifdef IP_RECVTOS
	int k = 0; socklen_t ks = sizeof(int);
	getsockopt(so,SOL_IP,IP_RECVTOS,&k,&ks);
	return k;
#else
	return false;
#endif
}

void IPSocket::setRecvTTL(bool recvttl)
{
#ifdef IP_RECVTTL
	int k = recvttl;
	setsockopt(so,SOL_IP,IP_RECVTTL,&k,sizeof(int));
#endif
}

int IPSocket::getRecvTTL()
{
#ifdef IP_RECVTTL
	int k = 0; socklen_t ks = sizeof(int);
	getsockopt(so,SOL_IP,IP_RECVTTL,&k,&ks);
	return k;
#else
	return 0;
#endif
}

void IPSocket::setTTL(int ttl)
{
#ifdef SOL_IP
	setsockopt(so,SOL_IP,IP_TTL,&ttl,sizeof(int));
#elif IPPROTO_IP
	setsockopt(so,IPPROTO_IP,IP_TTL,&ttl,sizeof(int));
#endif
}

int IPSocket::getTTL()
{
	int k = 0; socklen_t ks = sizeof(int);
#ifdef SOL_IP
	getsockopt(so,SOL_IP,IP_TTL,&k,&ks);
#elif IPPROTO_IP
	getsockopt(so,IPPROTO_IP,IP_TTL,&k,&ks);
#endif
	return k;
}

void IPSocket::setTOS(tos t)
{
#ifdef IPTOS_LOWDELAY
	int ts;
	switch (t) {
	case lowdelay: ts = IPTOS_LOWDELAY; break;
	case throughput: ts = IPTOS_THROUGHPUT; break;
	case reliability: ts = IPTOS_RELIABILITY; break;
	case mincost: ts = IPTOS_MINCOST; break;
	default: return;
	}
	setsockopt(so,SOL_IP,IP_TOS,&ts,sizeof(int));
#endif
}

IPSocket::tos IPSocket::getTOS()
{
#ifdef IPTOS_LOWDELAY
	int k = 0; socklen_t ks = sizeof(int);
	getsockopt(so,SOL_IP,IP_TOS,&k,&ks);
	switch (k) {
	case IPTOS_LOWDELAY: return lowdelay;
	case IPTOS_RELIABILITY: return reliability;
	case IPTOS_MINCOST: return mincost;
	default: return throughput;
	}
#else
	return throughput;
#endif
}

int IPSocket::getMTU()
{
#ifdef IP_MTU
	int k = 0; socklen_t ks = sizeof(int);
	getsockopt(so,SOL_IP,IP_MTU,&k,&ks);
	return k;
#else
	return 0;
#endif
}

TCPSocket::TCPSocket(int ext_sock, int backlog)
{
	so = ext_sock;
	if (so < 0) {
		err = Socket::FatalError;
		return;
	}
	sock_nonblock(so);
	if (listen(so,backlog) < 0) {
		err = Socket::FatalError;
		return;
	}
	to = 86400000;
}

TCPSocket::TCPSocket(const SocketAddress &b, int backlog)
{
	so = socket(PF_INET,SOCK_STREAM,6);
	if (so < 0) {
		
		err = Socket::FatalError;
		return;
	}
	sock_nonblock(so);
	prepare(b,backlog);
}

TCPSocket::~TCPSocket() { }

void TCPStream::flushCounters() { TCPStream_written = TCPStream_read = TCPStream_accept = TCPStream_connect = 0; }
unsigned TCPStream::bytesWrite() { return TCPStream_written; }
unsigned TCPStream::bytesRead() { return TCPStream_read; }
unsigned TCPStream::connAccept() { return TCPStream_accept; }
unsigned TCPStream::connConnect() { return TCPStream_connect; }

TCPStream::TCPStream(const SocketAddress &dst, unsigned connto, int bufsize) : StreamSocket(bufsize)
{
	so = socket(PF_INET,SOCK_STREAM,6);
	if (so < 0) {
		err = Socket::FatalError;
		return;
	}
	sock_nonblock(so);
	setTimeout(connto);
	connect(dst);
}

TCPStream::TCPStream(const SocketAddress &dst, const SocketAddress &b, unsigned connto, int bufsize) : StreamSocket(bufsize)
{
	so = socket(PF_INET,SOCK_STREAM,6);
	if (so < 0) {
		err = Socket::FatalError;
		return;
	}
	sock_nonblock(so);
	setReuseAddr();
	bind(b);
	setTimeout(connto);
	connect(dst);
}

TCPStream::TCPStream(int bufsize) : StreamSocket(bufsize)
{
	so = socket(PF_INET,SOCK_STREAM,6);
	if (so < 0) {
		err = Socket::FatalError;
		return;
	}
	sock_nonblock(so);
}

TCPStream::TCPStream(TCPSocket& acpt, int bufsize) : StreamSocket(bufsize)
{
	accept(acpt);
	EmergeBuffers();
}

TCPStream::TCPStream(TCPSocket& acpt, SocketAddress& peer, int bufsize) : StreamSocket(bufsize)
{
	accept(acpt,peer);
	EmergeBuffers();
}

TCPStream::~TCPStream() { }

UDPSocket::UDPSocket()
{
	so = socket(PF_INET,SOCK_DGRAM,17);
	if (so < 0) {
		err = Socket::FatalError;
		return;
	}
	sock_nonblock(so);
}
UDPSocket::~UDPSocket() { }

UnixSocket::UnixSocket() { }
UnixSocket::~UnixSocket() { }

int UnixSocket::getPeerPID() { int k; getPeer(&k, (int*)0, (int*)0); return k; }
int UnixSocket::getPeerUID() { int k; getPeer((int*)0, &k, (int*)0); return k; }
int UnixSocket::getPeerGID() { int k; getPeer((int*)0, (int*)0, &k); return k; }

void UnixSocket::getPeer(int *pid, int *uid, int *gid)
{
#ifndef __FreeBSD__
#ifdef SO_PEERCRED
	struct ucred cr;
	socklen_t crl = sizeof(struct ucred);
	getsockopt(so,SOL_SOCKET,SO_PEERCRED,&cr,&crl);
	if (pid) *pid = cr.pid;
	if (uid) *uid = cr.uid;
	if (gid) *gid = cr.gid;
#endif
#endif
}

UnixStreamServer::UnixStreamServer(const SocketAddress& addr, int backlog)
{
	so = socket(PF_UNIX,SOCK_STREAM,0);
	if (so < 0) {
		err = Socket::FatalError;
		return;
	}
	sock_nonblock(so);
	prepare(addr,backlog);
}

UnixStreamServer::~UnixStreamServer() { }

UnixStream::UnixStream(const SocketAddress& addr, unsigned connto, int bufsize) : StreamSocket(bufsize)
{
	so = socket(PF_UNIX,SOCK_STREAM,0);
	if (so < 0) {
		err = Socket::FatalError;
		return;
	}
	sock_nonblock(so);
	setTimeout(connto);
	connect(addr);
}

UnixStream::UnixStream(UnixStreamServer& str, int bufsize) : StreamSocket(bufsize)
{
	accept(str);
	EmergeBuffers();
}

UnixStream::~UnixStream() { }

UnixDatagramSocket::UnixDatagramSocket()
{
	so = socket(PF_UNIX,SOCK_DGRAM,0);
	if (so < 0) {
		err = Socket::FatalError;
		return;
	}
	sock_nonblock(so);
}

UnixDatagramSocket::~UnixDatagramSocket() { }

#if HAVE_SSL
static bool TCPSSL_ssl_init = false;
#endif

TCPSSLStream::TCPSSLStream(const SocketAddress &dst, const char *certname, const char *keyname, unsigned connto, int bufsize) : StreamSocket(bufsize), TCPStream(dst,connto,bufsize)
{
	ssl = (SSL*)0; ctx = (SSL_CTX*)0;
	if (!certname) ssl_connect();
	else ssl_connect(certname,(keyname?keyname:certname));
}

TCPSSLStream::TCPSSLStream(const SocketAddress &dst, unsigned connto, int bufsize) : StreamSocket(bufsize), TCPStream(dst,connto,bufsize)
{
	ssl = (SSL*)0; ctx = (SSL_CTX*)0;
	ssl_connect();
}

/// Connect to remote host from specific local address. bind is a local address.
TCPSSLStream::TCPSSLStream(const SocketAddress &dst, const SocketAddress &bind, unsigned connto, int bufsize) : StreamSocket(bufsize), TCPStream(dst,bind,connto,bufsize)
{
	ssl = (SSL*)0; ctx = (SSL_CTX*)0;
	ssl_connect();
}
	/// Accept connection from TCP stream server using SSL.
TCPSSLStream::TCPSSLStream(TCPSocket& acpt, const char *certname, const char *keyname, int bufsize) : StreamSocket(bufsize), TCPStream(acpt,bufsize)
{
	ssl = (SSL*)0; ctx = (SSL_CTX*)0;
	ssl_accept(certname,keyname?keyname:certname);
}

	/// Accept connection from TCP stream server using SSL with recognition of peer address.
TCPSSLStream::TCPSSLStream(TCPSocket& acpt, SocketAddress& peer, const char *certname, const char *keyname, int bufsize) : StreamSocket(bufsize), TCPStream(acpt,peer,bufsize)
{
	ssl = (SSL*)0; ctx = (SSL_CTX*)0;
	ssl_accept(certname,keyname?keyname:certname);
}

TCPSSLStream::TCPSSLStream(TCPSocket& acpt, int bufsize) : StreamSocket(bufsize), TCPStream(acpt,bufsize)
{
	ssl = (SSL*)0; ctx = (SSL_CTX*)0;
}

	/// Accept connection from TCP stream server using SSL with recognition of peer address.
TCPSSLStream::TCPSSLStream(TCPSocket& acpt, SocketAddress& peer, int bufsize) : StreamSocket(bufsize), TCPStream(acpt,peer,bufsize)
{
	ssl = (SSL*)0; ctx = (SSL_CTX*)0;
}

TCPSSLStream::TCPSSLStream(int bufsize) : StreamSocket(bufsize), TCPStream(bufsize) { ssl = (SSL*)0; ctx = (SSL_CTX*)0; }

TCPSSLStream::~TCPSSLStream()
{
#if HAVE_SSL
	if (ssl) {
		if (isClient) SSL_shutdown(ssl);
		SSL_free(ssl);
		ssl = (SSL*)0;
	}
	if (ctx) { SSL_CTX_free(ctx); ctx = (SSL_CTX*)0; }
#endif
}

#if HAVE_SSL

static int TCPSSL_bwrite(BIO *bio, const char *data, int size)
{
	for (;;) {
//#ifdef MSG_NOSIGNAL
//		int sz = send(bio->num,data,size,MSG_DONTWAIT|MSG_NOSIGNAL);
//#else
		sock_nonblock(bio->num);
		int sz = send(bio->num,data,size,0);
//#endif
		if (sz < 0)
			switch (errno) {
			case EMSGSIZE: return 0;
			case EWOULDBLOCK:
				if (!threads_waitonfd(bio->num,WAIT_WRITE,(unsigned)(bio->ptr))) {
					errno = ETIMEDOUT;
					return -1;
				}
				continue;
			case EINTR: continue;
			default: return -1;
			}
		
		return sz;
	}
}

static int TCPSSL_bread(BIO *bio, char *data, int size)
{
	for (;;) {
//#ifdef MSG_NOSIGNAL
//		int sz = recv(bio->num,data,size,MSG_DONTWAIT|MSG_NOSIGNAL);
//#else
		sock_nonblock(bio->num);
		int sz = recv(bio->num,data,size,0);
//#endif
		if (sz < 0)
			switch (errno) {
			case EWOULDBLOCK:
				if (!threads_waitonfd(bio->num,WAIT_READ,(unsigned)(bio->ptr))) {
					errno = ETIMEDOUT;
					return -1;
				}
				continue;
			case EINTR: continue;
			default: return -1;
			}
		return sz;
	}
}

static int TCPSSL_bputs(BIO *bio, const char *s)
{
	int n = strlen(s);
	return TCPSSL_bwrite(bio,s,n);
}

static long TCPSSL_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
	switch (cmd) {
	case BIO_C_SET_FD:
		bio->init = 1;
		bio->shutdown = BIO_NOCLOSE;
		bio->num = *(int*)ptr;
		return 1;
	case BIO_C_GET_FD:
		if (ptr) *(int*)ptr = bio->num;
		return bio->num;
	case BIO_CTRL_DUP:
	case BIO_CTRL_FLUSH:
		return 1;
	}
	
	return 0;
}

static int TCPSSL_dummy(BIO *) { return 1; }

static BIO_METHOD TCPSSL_bm = {
	/* int type = */ BIO_TYPE_SOCKET,
	/* const char *name = */ "threaded_sockets",
	TCPSSL_bwrite,
	TCPSSL_bread,
	TCPSSL_bputs,
	NULL,
	TCPSSL_ctrl,
	TCPSSL_dummy,
	TCPSSL_dummy,
	NULL
};

#endif

void TCPSSLStream::ssl_connect(const char *certname, const char *keyname)
{
	isClient = true;
#if HAVE_SSL
	SSL_METHOD *meth;
	if (!TCPSSL_ssl_init) {
		SSL_load_error_strings();
		SSLeay_add_ssl_algorithms();
		TCPSSL_ssl_init = true;
	}
	meth = SSLv23_client_method();
	if (!meth) { shutdown(); err = Socket::SSLFailure; return; }
	ctx = SSL_CTX_new(meth);
	if (!ctx) { shutdown(); err = Socket::SSLFailure; return; }

	// Add to contect client certificate
	if (SSL_CTX_use_certificate_file(ctx,certname,SSL_FILETYPE_PEM) <= 0) {
		SSL_CTX_free(ctx); ctx = (SSL_CTX*)0;
		shutdown(); err = Socket::SSLFailure; return;
	}
	if (SSL_CTX_use_PrivateKey_file(ctx,keyname,SSL_FILETYPE_PEM) <= 0) {
		SSL_CTX_free(ctx); ctx = (SSL_CTX*)0;
		shutdown(); err = Socket::SSLFailure; return;
	}
	if (SSL_CTX_check_private_key(ctx) <= 0) {
		SSL_CTX_free(ctx); ctx = (SSL_CTX*)0;
		shutdown(); err = Socket::SSLFailure; return;
	}
	
	ssl = SSL_new(ctx);
	if (!ssl) { SSL_CTX_free(ctx); ctx = (SSL_CTX *)0; shutdown(); err = Socket::SSLFailure; return; }
	BIO *rbio = BIO_new(&TCPSSL_bm);
	if (!rbio) { SSL_free(ssl); ssl = (SSL*)0;SSL_CTX_free(ctx); ctx = (SSL_CTX *)0; shutdown(); err = Socket::SSLFailure; return; }
	BIO *wbio = BIO_new(&TCPSSL_bm);
	if (!wbio) { BIO_free(rbio); SSL_free(ssl); ssl = (SSL*)0;SSL_CTX_free(ctx); ctx = (SSL_CTX *)0; shutdown(); err = Socket::SSLFailure; return; }
	rbio->shutdown = wbio->shutdown = BIO_NOCLOSE;
	rbio->num = wbio->num = so;
	rbio->init = wbio->init = 1;
	rbio->ptr = wbio->ptr = (void*)to;
	SSL_set_bio(ssl,rbio,wbio);
	while (SSL_connect(ssl) <= 0) {
		SSL_free(ssl);
		SSL_CTX_free(ctx);
		ctx = (SSL_CTX*)0; ssl = (SSL*)0;
		shutdown();
		err = Socket::SSLFailure;
		return;
	}
#else
	shutdown();
	err = Socket::NoSSL;
#endif
}

void TCPSSLStream::ssl_connect()
{
	isClient = true;
#if HAVE_SSL
	SSL_METHOD *meth;
	if (!TCPSSL_ssl_init) {
		SSL_load_error_strings();
		SSLeay_add_ssl_algorithms();
		TCPSSL_ssl_init = true;
	}
	meth = SSLv23_client_method();
	if (!meth) { shutdown(); err = Socket::SSLFailure; return; }
	ctx = SSL_CTX_new(meth);
	if (!ctx) { shutdown(); err = Socket::SSLFailure; return; }
	ssl = SSL_new(ctx);
	if (!ssl) { SSL_CTX_free(ctx); ctx = (SSL_CTX *)0; shutdown(); err = Socket::SSLFailure; return; }
	BIO *rbio = BIO_new(&TCPSSL_bm);
	if (!rbio) { SSL_free(ssl); ssl = (SSL*)0;SSL_CTX_free(ctx); ctx = (SSL_CTX *)0; shutdown(); err = Socket::SSLFailure; return; }
	BIO *wbio = BIO_new(&TCPSSL_bm);
	if (!wbio) { BIO_free(rbio); SSL_free(ssl); ssl = (SSL*)0;SSL_CTX_free(ctx); ctx = (SSL_CTX *)0; shutdown(); err = Socket::SSLFailure; return; }
	rbio->shutdown = wbio->shutdown = BIO_NOCLOSE;
	rbio->num = wbio->num = so;
	rbio->init = wbio->init = 1;
	rbio->ptr = wbio->ptr = (void*)to;
	SSL_set_bio(ssl,rbio,wbio);
	while (SSL_connect(ssl) <= 0) {
		SSL_free(ssl);
		SSL_CTX_free(ctx);
		ctx = (SSL_CTX*)0; ssl = (SSL*)0;
		shutdown();
		err = Socket::SSLFailure;
		return;
	}
#else
	shutdown();
	err = Socket::NoSSL;
#endif
}

void TCPSSLStream::ssl_accept(const char *certname, const char *keyname)
{
	isClient = false;
#if HAVE_SSL
	SSL_METHOD *meth;
	if (!TCPSSL_ssl_init) {
		SSL_load_error_strings();
		SSLeay_add_ssl_algorithms();
		TCPSSL_ssl_init = true;
	}
	meth = SSLv23_server_method();
	if (!meth) { shutdown(); err = Socket::SSLFailure; return; }
	ctx = SSL_CTX_new(meth);
	if (!ctx) { shutdown(); err = Socket::SSLFailure; return; }
	if (SSL_CTX_use_certificate_file(ctx,certname,SSL_FILETYPE_PEM) <= 0) {
		SSL_CTX_free(ctx); ctx = (SSL_CTX*)0;
		shutdown(); err = Socket::SSLFailure; return;
	}
	if (SSL_CTX_use_PrivateKey_file(ctx,keyname,SSL_FILETYPE_PEM) <= 0) {
		SSL_CTX_free(ctx); ctx = (SSL_CTX*)0;
		shutdown(); err = Socket::SSLFailure; return;
	}
	if (SSL_CTX_check_private_key(ctx) <= 0) {
		SSL_CTX_free(ctx); ctx = (SSL_CTX*)0;
		shutdown(); err = Socket::SSLFailure; return;
	}
	ssl = SSL_new(ctx);
	if (!ssl) { SSL_CTX_free(ctx); ctx = (SSL_CTX *)0; shutdown(); err = Socket::SSLFailure; return; }
	BIO *rbio = BIO_new(&TCPSSL_bm);
	if (!rbio) { SSL_free(ssl); ssl = (SSL*)0;SSL_CTX_free(ctx); ctx = (SSL_CTX *)0; shutdown(); err = Socket::SSLFailure; return; }
	BIO *wbio = BIO_new(&TCPSSL_bm);
	if (!wbio) { BIO_free(rbio); SSL_free(ssl); ssl = (SSL*)0;SSL_CTX_free(ctx); ctx = (SSL_CTX *)0; shutdown(); err = Socket::SSLFailure; return; }
	rbio->shutdown = wbio->shutdown = BIO_NOCLOSE;
	rbio->num = wbio->num = so;
	rbio->init = wbio->init = 1;
	rbio->ptr = wbio->ptr = (void*)to;
	SSL_set_bio(ssl,rbio,wbio);
	while (SSL_accept(ssl) <= 0) {
		SSL_free(ssl);
		SSL_CTX_free(ctx);
		ctx = (SSL_CTX*)0; ssl = (SSL*)0;
		shutdown();
		err = Socket::SSLFailure;
		return;
	}
#else
	shutdown();
	err = Socket::NoSSL;
	return;
#endif
}

int TCPSSLStream::ssl_send(const void *msg, unsigned len)
{
#if HAVE_SSL
	if (!ssl) { err = Socket::SSLFailure; return 0; }
	for (;;) {
		int sz = SSL_write(ssl,(const char*)msg,len);
		switch (SSL_get_error(ssl,sz)) {
		case SSL_ERROR_NONE: if (sz < 0) return 0; break;
		case SSL_ERROR_WANT_WRITE: if (sz < 0) continue; break;
		case SSL_ERROR_WANT_READ: if (sz < 0) continue; break;
		case SSL_ERROR_SYSCALL:
			switch (errno) {
			case ETIMEDOUT: err = Socket::TimedOut; return 0;
			case EINTR: continue;
			case ECONNREFUSED: err = Socket::ConnectionRefused; return 0;
			case ENOTCONN: case EPIPE: err = Socket::NotConnected; return 0;
			default: err = Socket::FatalError; return 0;
			}
			break;
		default: err = Socket::FatalError; return 0;
		}
		
		return sz;
	}
#else
	err = Socket::NoSSL;
	return 0;
#endif
}

int TCPSSLStream::ssl_recv(void *buf, size_t len)
{
#if HAVE_SSL
	if (!ssl) { err = Socket::SSLFailure; return 0; }
	for (;;) {
		int sz = SSL_read(ssl,(char*)buf,len);
		switch (SSL_get_error(ssl,sz)) {
		case SSL_ERROR_NONE: if (sz < 0) return 0; break;
		case SSL_ERROR_WANT_WRITE: if (sz < 0) continue; break;
		case SSL_ERROR_WANT_READ: if (sz < 0) continue; break;
		case SSL_ERROR_SYSCALL:
			switch (errno) {
			case ETIMEDOUT: err = Socket::TimedOut; return 0;
			case EINTR: continue;
			case ECONNREFUSED: err = Socket::ConnectionRefused; return 0;
			case ENOTCONN: case EPIPE: err = Socket::NotConnected; return 0;
			default: err = Socket::FatalError; return 0;
			}
			break;
		default: err = Socket::FatalError; return 0;
		}
					     
		return sz;
	}
#else
	err = Socket::NoSSL;
	return 0;
#endif
}

int TCPSSLStream::underflow()
{
	if (err != Socket::OK || !eback()) return EOF;
	if (gptr() < egptr())
		return (unsigned char)*gptr();

	int rlen = (gbuf+bufsize) - eback();
	rlen = ssl_recv(eback(),rlen);
	if (err != Socket::OK) return EOF;

	if (rlen < 1)
		return EOF;

	gpos += egptr() - eback();
	setg(eback(),eback(),eback()+rlen);

	return (unsigned char)*gptr();
}

int TCPSSLStream::overflow(int ch)
{
	if (err != Socket::OK || !pbase()) return EOF;
	streamsize len = pptr() - pbase();
	if (len == 0 && ch == EOF) return 0;
	if (ch != EOF) { *pptr() = ch; len ++; }
	int cur = 0;
	setp(pbase(),epptr());
	while (len > 0) {
		int wsz = 0;
		wsz = ssl_send(pbase()+cur,len);
		if (err != Socket::OK) return EOF;
		cur += wsz;
		ppos += wsz;
		len -= wsz;
		if (wsz == 0) return EOF;
	}

	return 0;
}

int TCPSSLStream::sync() { return overflow(EOF); }

};

namespace handylib {

static unsigned Thread_tod_init = 0;
static struct timeval Thread_tod_tv;
static pthread_key_t Thread_key;
static pthread_once_t Thread_key_once = PTHREAD_ONCE_INIT;
static int Thread_count = 0;

static void Thread_key_destroy(void *p)
{
	if (((Thread*)p)->f_autodelete) delete ((Thread*)p);
	--Thread_count;
}
Thread *getThread() { return (Thread*)pthread_getspecific(Thread_key); }
static void Thread_key_init(void) { pthread_key_create(&Thread_key, Thread_key_destroy); }
static void Thread_key_bind(Thread *th)
{
	pthread_once(&Thread_key_once, Thread_key_init);
	pthread_setspecific(Thread_key,th);
	++Thread_count;
}

unsigned Timer::getCurrent(void) const
{
	struct timeval tv;
	
	gettimeofday(&tv, (struct timezone*)0);

	if (!Thread_tod_init) {
		Thread_tod_tv.tv_sec = tv.tv_sec-1;
		Thread_tod_init = 1;
	}

	tv.tv_sec -= Thread_tod_tv.tv_sec;

	unsigned secs = (unsigned)(tv.tv_sec & 0x1FFFFFF);
	secs *= 125;
	secs >>= 1;

	return tv.tv_usec / 16000 + secs;
}

Thread::Thread(int stacksize)
{
	f_autodelete = false;
	f_stacksize = stacksize;
	f_next = f_prev = (Thread*)0;
	f_sleep.endTimer();
	f_state = Thread::THREAD_INITIAL;
	f_cancel = false;
	stack = (char*)new pthread_t;
	onexit = 0;
}

Thread::Thread(const Thread& fib)
{
	f_autodelete = false;
	f_stacksize = fib.f_stacksize;
	f_next = f_prev = (Thread*)0;
	f_sleep.endTimer();
	f_state = Thread::THREAD_INITIAL;
	f_cancel = false;
	stack = (char*)new pthread_t;
	onexit = 0;
}

Thread::~Thread()
{
	Terminate();
	if (stack) delete stack;
	stack = (char*)0;
}

void Thread::Sleep(unsigned msec) { threads_sleep(msec); }
void Thread::Yield() { if (testCancel()) return; threads_yield(); }

void Thread::Terminate()
{
	if (!stack) return;
	if (f_state == Thread::THREAD_INITIAL || f_state == Thread::THREAD_TERMINATE) return;
	if (f_state == Thread::THREAD_RUNNING) f_state = Thread::THREAD_TERMINATE;
	pthread_cancel(*(pthread_t*)stack);
}

void Thread::Suspend() { pthread_kill(*(pthread_t*)stack,SIGSTOP); }
void Thread::Resume() { pthread_kill(*(pthread_t*)stack,SIGCONT); }
void Thread::Initial() { return; }
void Thread::Final() { return; }

static void *thread_initialize(void *p) { ((Thread*)p)->doInit();/* if (((Thread*)p)->f_autodelete) delete ((Thread*)p); */ return NULL; }

void Thread::wakeThread() { pthread_kill(*(pthread_t*)stack,SIGCHLD); }

void Thread::doInit()
{
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	f_state = Thread::THREAD_RUNNING;
	Thread_key_bind(this);
	Initial();
	Run();
	Final();
	if (onexit) (*onexit)(this);
	f_state = Thread::THREAD_TERMINATE;
}

void Thread::Start()
{
	if (!stack) { f_cancel = true; return; }
	if (f_state != Thread::THREAD_INITIAL) return;
	f_cancel = false;
	pthread_attr_t att;
	pthread_attr_init(&att);
	pthread_attr_setdetachstate(&att,PTHREAD_CREATE_DETACHED);
	f_state = Thread::THREAD_RUNNING;
	if (pthread_create((pthread_t*)stack, &att, &thread_initialize, this))
		f_state = Thread::THREAD_TERMINATE;
	pthread_attr_destroy(&att);
}

unsigned threads_yield() { return 0; }
 
void threads_sleep(unsigned ms)
{
	Thread *p = getThread();
	if (p && p->testCancel()) return;
	struct timespec tv, rem;
	tv.tv_sec = ms / 1000;
	tv.tv_nsec = 1000000 * (ms % 1000);
	nanosleep(&tv,&rem);
	return;
}

void threads_mainloop()
{
	while (Thread_count > 0) threads_sleep(10000);
}

bool threads_waitonfd(int fd, int wait, unsigned to)
{
	Thread *p = getThread();
	if (p && p->testCancel()) return false;
	struct pollfd pf;
	pf.fd = fd;
	pf.revents = pf.events = 0;
	if (wait & WAIT_WRITE) pf.events |= POLLOUT;
	if (wait & WAIT_READ) pf.events |= POLLIN;
	if (wait & WAIT_EX) pf.events |= POLLERR | POLLNVAL;
	int tom = to;
	if (to == Timer::inf) tom = -1;
	for (;;) {
		tom = poll(&pf,1,tom);
		if (tom == 0) return false;
		if (tom == 1) return true;
		if (errno == EINTR) {
			Thread *p = getThread();
			if (p && p->testCancel()) return false;
			continue;
		}
		return false;
	}
}

bool Thread::WaitOnFD(int fd, int wait, unsigned to) { return threads_waitonfd(fd,wait,to); }

};

using namespace std;

namespace handylib {

static char tm_tzname[8];
static int tm_tz, tm_rtz;
int Time_dummy_int;

string Time::formatHTTP() { if (tz() != 0) xtz() = 0; return format("%a, %d %b %Y %H:%M:%S GMT"); }

void Time::parseHTTP(const char *str)
{
	if (tz() != 0) xtz() = 0;
	if (seconds() != 0) xseconds() = 0;
	if (!strchr(str,',')) {
		parse("%a %b %d %H:%M:%S %Y",str);
		return;
	}
	parse("%a, %d-%b-%Y %H:%M:%S",str);
	if (seconds() != 0) return;
	parse("%A, %d-%b-%y %H:%M:%S",str);
	if (seconds() != 0) return;
	parse("%a, %d %b %Y %H:%M:%S",str);
	return;
}

static void fmtutc(char *s, int tz, int t)
{
	int tzh, tzm, tzx;

	tzx = tz; if (tzx < 0) tzx = -tzx;
	tzm = tzx / 60;
	tzh = tzm / 60;
	tzm %= 60;
	tzh %= 24;
	if (t != 0) tzm = 0;

	if (tzh == 0 && t == 2) {
		s[0] = s[1] = '0'; s[2] = 0; return;
	} else if ((tzh == 0 && t == 1) || (tz == 0 && t == 0)) {
		s[0] = s[1] = s[2] = s[3] = '0'; s[4] = 0; return;
	}

	if (tz >= 0)
		snprintf(s,7,(t!=2?"+%02d%02d":"+%02d"),tzh,tzm);
	else
		snprintf(s,7,(t!=2?"-%02d%02d":"-%02d"),tzh,tzm);
}


void Time::lcache() const
{
	if (!cache) cache = new Cache;
	if (!cache) return;
	time_t tt = secs + tm_rtz - tzi;
	struct tm *t = localtime(&tt);
	if (!t) { delete [] cache; return; }
	cache->sec = t->tm_sec;
	cache->min = t->tm_min;
	cache->hour = t->tm_hour;
	cache->mday = t->tm_mday;
	cache->mon = t->tm_mon;
	cache->year = t->tm_year;
	cache->wday = t->tm_wday;
	cache->yday = t->tm_yday;
	if (tzi == tm_tz)
		strcpy(cache->tzname, tm_tzname);
	else
		fmtutc(cache->tzname, tzi, 0);
}

void Time::scache() const
{
	struct tm t;
	t.tm_sec = cache->sec;
	t.tm_min = cache->min;
	t.tm_hour = cache->hour;
	t.tm_mday = cache->mday;
	t.tm_mon = cache->mon;
	t.tm_year = cache->year;
	t.tm_wday = cache->wday;
	t.tm_yday = cache->yday;
	t.tm_isdst = 0;
	secs = mktime(&t);
	if (secs == (time_t)(-1)) secs = 0;
	else secs += tzi - tm_rtz;
}

void Time::ucache() const
{
	delete cache;
	cache = (Cache*)0;
}

Time::Time(const char *ts) {
	cache = (Cache*)0;
	tzi = gettz();
	parse("%Y%m%d%H%M%S", ts);
	if (!seconds()) {
		parse("%Y-%m-%d %H:%M:%S", ts);
		if (!seconds()) parse("%Y-%m-%d",ts);
	}
}

string Time::timestamp(int len) const
{
	switch (len) {
	case 14: return format("%Y%m%d%H%M%S");
	case 12: return format("%Y%m%d%H%M");
	case 10: return format("%Y%m%d%H");
	case 8: return format("%Y%m%d");
	case 6: return format("%y%m%d");
	}
	return string();
}

Time& Time::now()
{
	secs = time((time_t*)0);
	if (cache) lcache();
	return *this;
}

//	 %% - a % character.
//	 %a - abbreviated weekday name (Sun..Sat)
//	 %A - full weekday name (Sunday..Saturday)
//	 %b - abbreviated month name (Jan..Dec)
//	 %B - full month name (January..December)
//	 %d - day of month (01..31)
//	 %e - day of month blank padded ( 1..31)
//	 %H - hour (00..23)
//	 %I - hour (01..12)
//	 %j - day of year (001..366)
//	 %k - hour ( 0..23)
//	 %l - hour ( 1..23)
//	 %m - month (01..12)
//	 %M - minute (00..59)
//	 %p - AM or PM
//	 %s - seconds since 00:00:00, Jan 1, 1970
//	 %S - second (00..60)
//	 %t - time zone name (GMT, UTC, ...) if unknown then %T will be used.
//	 %T - UTC time zone (-0215, 0000, +0324, ...)
//	 %u - UTC time zone hours (-0200, 0000, +0300, ...)
//	 %U - UTC time zone (-02, 00, +03, ...)
//	 %w - day of week (0..6) 0 = Sunday
//	 %y - last two digits of year
//	 %Y - year (1970...)

static const char *weekdaya[7] = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
static const char *weekday[7] = {"Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"};
static const char *montha[12] = {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
static const char *month[12] = {"January","February","March","April","May","June","July","August","September","October","November","December"};

string Time::format(const char *fmt) const
{
	stringstream s;
	const char *p;
	char tzt[8];

	for (p = fmt; *p; p++) if (*p == '%') { switch (p[1]) {
	case '%': s << '%'; break;
	case 'a': s << weekdaya[wday()]; break;
	case 'A': s << weekday[wday()]; break;
	case 'b': s << montha[mon()]; break;
	case 'B': s << month[mon()]; break;
	case 'd': s << setfill('0') << setw(2) << mday(); break;
	case 'e': s << setfill(' ') << setw(2) << mday(); break;
	case 'H': s << setfill('0') << setw(2) << hour(); break;
	case 'I': s << setfill('0') << setw(2) << (hour()%12); break;
	case 'j': s << setfill('0') << setw(3) << yday(); break;
	case 'k': s << setfill(' ') << setw(2) << hour(); break;
	case 'l': s << setfill(' ') << setw(2) << (hour()%12); break;
	case 'm': s << setfill('0') << setw(2) << (mon()+1); break;
	case 'M': s << setfill('0') << setw(2) << min(); break;
	case 'p': if (hour() >= 12) s << "PM"; else s << "AM"; break;
	case 's': s << seconds(); break;
	case 'S': s << setfill('0') << setw(2) << sec(); break;
	case 'w': s << wday(); break;
	case 't': s << tzname(); break;
	case 'T': fmtutc(tzt,tz(),0); s << tzt;break;
	case 'u': fmtutc(tzt,tz(),1); s << tzt;break;
	case 'U': fmtutc(tzt,tz(),2); s << tzt;break;
	case 'y': s << setfill('0') << setw(2) << (year()%100); break;
	case 'Y': s << setw(4) << (year()+1900); break;
	default: break;
	} p++; } else s << *p;

	return s.str();
}

static int tm_scan_str(const char **str, const char **av, int sz)
{
	int i;
	for (i = 0; i < sz; i++)
		if (!strncmp(*str,av[i],strlen(av[i]))) {
			*str += strlen(av[i]);
			return i;
		}
	return 0;
}

static int tm_scan_int(const char **str, int max)
{
	if (max == 2) {
		if (isdigit(**str) && isdigit((*str)[1])) {
			char c[3]; c[0] = **str; c[1] = (*str)[1]; c[2] = 0;
			*str += 2;
			return atoi(c);
		}
	}
	if (max == 4) {
		if (isdigit(**str) && isdigit((*str)[1]) && isdigit((*str)[2]) && isdigit((*str)[3])) {
			char c[5]; c[0] = **str;
		       	c[1]=(*str)[1]; c[2]=(*str)[2]; c[3]=(*str)[3]; c[4] = 0;
			*str += 4;
			return atoi(c);
		}
	}
	char *ep;
	int x = (int)strtol(*str,&ep,10);
	*str = ep;
	return x;
}

static void tm_skip_spaces(const char **str)
{
	while (**str == ' ' || **str == '\t' || **str == '\n' || **str == '\r')
		(*str)++;
}

static int scnutc(const char **str, int sz)
{
	int sign = 1, tzv;
	if (**str == '-') { sign = -1; (*str)++; }
	if (**str == '+') { sign = 1; (*str)++; }
	tzv = tm_scan_int(str,sz);
	if (sz == 2) tzv *= 3600;
	else tzv = (tzv % 100) * 60 + (tzv / 100) * 3600;
	tzv *= sign;
	return tzv;
}

void Time::parse(const char *fmt, const char *str)
{
	const char *p, *sp;
	bool fixpm = false, pm = false;

	for (p = fmt, sp = str; *p && *sp; p++) if (*p == '%') { switch (p[1]) {
	case '%': if (*sp++ != '%') { erase(); return; } break;
	case 'a': tm_scan_str(&sp,weekdaya,7); break;
	case 'A': tm_scan_str(&sp,weekday,7); break;
	case 'b': xmon() = tm_scan_str(&sp,montha,12); break;
	case 'B': xmon() = tm_scan_str(&sp,month,12); break;
	case 'd': case 'e': if (!isdigit(*sp)) { erase(); return; } xmday() = tm_scan_int(&sp,2); break;
	case 'H': case 'k': if (!isdigit(*sp)) { erase(); return; } xhour() = tm_scan_int(&sp,2); break;
	case 'I': case 'l': if (!isdigit(*sp)) { erase(); return; } fixpm = true; xhour() = tm_scan_int(&sp,2); break;
	case 'j': if (!isdigit(*sp)) { erase(); return; } tm_scan_int(&sp,2); break;
	case 'm': if (!isdigit(*sp)) { erase(); return; } xmon() = tm_scan_int(&sp,2)-1; break;
	case 'M': if (!isdigit(*sp)) { erase(); return; } xmin() = tm_scan_int(&sp,2); break;
	case 's': if (!isdigit(*sp)) { erase(); return; } xseconds() = tm_scan_int(&sp,0); break;
	case 'S': if (!isdigit(*sp)) { erase(); return; } xsec() = tm_scan_int(&sp,2); break;
	case 'p': if (sp[0] == 'p' || sp[0] == 'P') pm = true; sp++; if (*sp == 'M' || *sp == 'm') sp++; break;
	case 'T': xmtz() = scnutc(&sp,4); break;
	case 'u': xmtz() = scnutc(&sp,4); break;
	case 'U': xmtz() = scnutc(&sp,2); break;
	case 'y': if (!isdigit(*sp)) { erase(); return; } xyear() = 100 + tm_scan_int(&sp,2); break;
	case 'Y': if (!isdigit(*sp)) { erase(); return; } xyear() = tm_scan_int(&sp,4) - 1900; break;
	default: break;
	} p++; } else if (*p == ' ') tm_skip_spaces(&sp); else if (*sp++ != *p) { erase(); break; }

	if (fixpm && pm) xhour() += 12;
}

const char *Time::tzname() const
{
	if (!cache) lcache();
	if (!cache->tzname[0]) fmtutc(cache->tzname,tz(),0);
	return cache->tzname;
}

static void tm_loadtzi()
{
	struct tm *tm;
	time_t tt;

	time(&tt);
	tm = localtime(&tt);
	strncpy(tm_tzname,tzname[0],7);
	#if !defined(__FreeBSD__) && !defined(__MACH__)
	tm_rtz = tm_tz = timezone;
	#else
	tm_rtz = tm_tz = tm->tm_gmtoff;
	#endif
}

int Time::gettz()
{
	if (!tm_tzname[0]) tm_loadtzi();
	return tm_tz;
}

void Time::settz(int tz)
{
	if (!tm_tzname[0]) tm_loadtzi();
	tm_tz = tz;
	fmtutc(tm_tzname,tz,0);
}

void Time::settzname(const char *s)
{
	strncpy(tm_tzname,s,7);
}

const char *Time::gettzname()
{
	if (!tm_tzname[0]) tm_loadtzi();
	return tm_tzname;
}

void Time::getEnclosingWeek(Time& start, Time& end)
{
	if (&start != this) start = *this;

	start.xseconds() ++; start.xseconds() --;
	while (start.wday() != 1) { start.xseconds() -= 86400; }

	end = start;
	end.xseconds() ++; end.xseconds() --;
	while (end.wday() != 0) { end.xseconds() += 86400; }

	start.xhour() = 0; start.xmin() = 0; start.xsec() = 0;
	end.xhour() = 23; end.xmin() = 59; end.xsec() = 59;
}

};

