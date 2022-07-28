def zap_started(zap, target):
	zap.script.load('authScript', 'authentication', 'Mozilla Zest', '/zap/wrk/authScript')