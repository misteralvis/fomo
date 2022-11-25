#!/usr/bin/python

from fomo import cloudwatch as cw

#--- Use AWS credentials set in env
dft_session = cw.Session()

#--- Use AWS credentials set in env, but specify which Region
dft_session_east1 = cw.Session(region_name="us-east-1")
dft_session_east2 = cw.Session(region_name="us-east-2")
dft_session_west1 = cw.Session(region_name="us-west-1")
dft_session_west2 = cw.Session(region_name="us-west-2")

#--- Specify AWS credentials inline, retrieved from AWS Console or otherwise
# 1 : Access Key ID
# 2 : Secret Access key
# 3 : Session Token
# 4 : region
specified_session = cw.Session("ASIAZM37WPFP4FMGOD6M", "IKG9KNTAWbkqCALE2Jm9ni4cwklD4hcrgmH11d3F", "IQoJb3JpZ2luX2VjEFYaCXVzLWVhc3QtMSJGMEQCIBeO9wBmycFGeq/F7UHbCz1uz69KPnIRU1VzBkgvXyQlAiBxB7SUz6syrI9PkMUFhAlcQEZ3+4MXOkq2uh9Lq79qAiqHAwgvEAMaDDY0NjEyMzUxODMwMyIMaPrL49Sb8a7dlCfkKuQCkxNciB28iyR8f7fdgNSKljI4aHGTXaWDRgpkqV2vWsyXAy2fBEHlYM5u87FtUJxKVq+TQyhlU7QuCsweKupfjy3F3UH8wBr7/OiTZU0uE47KfSyClktwlEVYEPW9UxQAMRgSk0gdr54Z/MfanpuKs3hX1Dai49eY8c7Ncvw/7uN3PimMAIe5wcWcEM+SOgMyUSMqYwe2sHzuBT6cDPxRBdkfiNOhdU9Shf9zl4A9znkc3jIYjmNEQELXhRcffnacOgvUwaoRSdqyzpqmWBg+p59nQGGuP7cHmUuT4heEYypXyVDnmDgEKkKsJzRK7KRUR2EvUylu715oIkhnQakAx1sQZfo8cNWVumjq0fys71SLAKot665gAuRXH4e5bM2OYvSbDDxixsIjJgxattQ0NpAWG+AK7oY2OrzjXBxUqaTHZYj6VmehM5yi/Jd8lKULdGd6/MR+Bl297n55tbfi192li28w4eC6mgY6pwF0IjJ83YZD+gtRIDbq1SgxOigitL6PcUI0PCvnH12wgjhXpNn0aCmuF19vjeCO5Yb1QMa93k02CYDVF4bnF1sou2dK/W9q8wnvxUTf4O/BcqIucEPTWJy1AsITZWsR4/Lh9GiSPRmshL9axVXUPvF63XwhgfuZ2vHFOjHb3rCMxdqRFWxBAbJCB0o/vB28crnV5HFZ3goUZApwR0rmQlIeX0nq7EctFA==", "us-east-1")

#--- Some example commands, using dft_session established above
#--- All of these objects are represented as dict type (dictionaries)
all_alarms = dft_session.get_all_alarms()
all_dashboards = dft_session.get_all_dashboards()
all_sns = dft_session.get_all_sns()

#--- Print a functions description
print(cw.filter_metric_alarms.__doc__)

#--- Filter your alarms using above method
scam_shield_alarms = cw.filter_metric_alarms(all_alarms,"[Scam Shield Backend Service]")

#--- Pretty printing format
cw.print_alarms(scam_shield_alarms)

#--- Rename an alarm. You can choose to retain the old version
dft_session.rename_alarm("Old alarm name","New alarm name",keep_old_alarm=False)

#--- Enable / Disable an alarm
dft_session.enable_alarm("Alarm name")
dft_session.disable_alarm("Alarm name")
