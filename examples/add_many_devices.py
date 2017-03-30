from zenoss import Zenoss
import json

rm = Zenoss('http://your.rm.instance.loc/', 
            username = 'you', password = 'password',
            #cert='/path/to/your.cert.pem',
            ssl_verify=False
           )

device_list = ['10.160.32.{}'.format(i) for i in range(1,100)]

for dev_name in device_list:

    #out = rm.remove_device(
    #    device_name=dev_name,
    #)

    out = rm.add_device(
        device_name=dev_name,
        device_class='/Server/Linux',
        model=True,
        manageIp=dev_name
    )
    print(out)


