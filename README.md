#Prerequisits
Have ~/.aws folder created with credentails.csv containing the API keys in the same format given by AWS.
## pip requirments
1. boto3
2. requests

#How to run:

<pre><code>
python3 add_ip_addr.py --security_group="Id of your security group" --region="Your AWS region"
</pre></code>
security_group is a mandatory argument
Region defaults to ap-south-1

