def valid():
    def make_sec_val(self, val):
        return '%s|%s' % (val, hmac.new(secret, val).hexdigest())
    def check_sec_val(self, sec_val):
        val = sec_val.split('|')[0]
        if sec_val == self.make_sec_val(val):
            return val
    def set_sec_cookie(self, name, val):
        cookie_val = self.make_sec_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))
    def read_sec_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and self.check_sec_val(cookie_val)
