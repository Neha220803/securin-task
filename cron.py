import crontab

my_cron = crontab.CronTab(user=True)
job = my_cron.new(command='app.py')

job.minute.on(0)
job.hour.on(5)

my_cron.write()
