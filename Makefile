.PHONY: demo setup-local telegram-local telegram-down telegram-logs telegram-reset check test

demo:
	npm run demo

setup-local:
	npm run setup:local

telegram-local:
	npm run telegram:local

telegram-down:
	npm run telegram:down

telegram-logs:
	npm run telegram:logs

telegram-reset:
	npm run telegram:reset

check:
	npm run check

test:
	npm test
