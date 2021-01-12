import json
import hashlib
import boto3
from botocore.exceptions import ClientError
import os

region = os.environ['AWS_REGION']
logs_bucket = os.environ['logs_bucket']
GG_UID = os.environ['GG_UID']
tableName = os.environ['tableName']

s3_client = boto3.client('s3', region_name=region)
dynamodb_client = boto3.resource('dynamodb', region_name=region)

# SHA 256 hashing algorithm is widely used in security applications and protocols. The following python program computes the SHA256 hash value of a file. Note that the computed hash is converted to a readable hexadecimal string
def calculate_hash(filename):
    with open(filename,"rb") as f:
        bytes = f.read() # read entire file as bytes
        readable_hash = hashlib.sha256(bytes).hexdigest();
        return(readable_hash)

def notify_mismatch_hash(DDB_hash, s3_file):
    calculated_hash = calculate_hash(s3_file)
    
    return ''

def unzipFiles(s3_file):
    return []

def compare_hashes(file, DDB_hash):
    calculated_hash = calculate_hash(file)
    print("Hash Calculated:")
    print(calculated_hash)
    print("Hash fetched from DynamoDB:")
    print(DDB_hash)
    if calculated_hash != DDB_hash:
        return False
    return True
    
    
def get_timestamp_log_file(filename):
    start = filename.find("log-") + len("log-")
    end = filename.find(".zip")
    timestamp = filename[start:end]
    return timestamp
    
def get_ddb_item(filename):
    timestamp = get_timestamp_log_file(filename)
    table = dynamodb_client.Table(tableName)
    try:
        attrs = table.attribute_definitions
        response = table.get_item(Key={'GG_ID': str(GG_UID), 'timestamp': int(timestamp)})
    except ClientError as e:
        print(e.response['Error']['Message'])
    else:
        return response['Item']

def check_zip_artifacts(s3_file, DDB_item):
    files = unzipFiles(s3_file)
    # How to map the unzipped files and the hashes in DynamoDB would depend on the naming chosen - Still to be done based on requirements
    for file in files:
        # Retrieve Hash from DynamoDB for the specific file using the file name
        # TO DO: file_name = get_file_name(file)
        compare_hashes(file, DDB_item["filesHashes"][file_name])
    return True
        
def get_log_file_name(event):
    # Can loop through Records in the event object ; in our case we only take 1 record as the lambda will be triggered on each new SQS Message
    event_body = json.loads(event['Records'][0]['body'])
    log_file_name = event_body['Records'][0]['s3']['object']['key']
    return log_file_name
        

def lambda_handler(event, context):
    # An Event received from SQS will look like this one: 
    # event = {'Records': [{'messageId': 'd9386eb3-853a-4b07-859f-a2ac87be8b40', 'receiptHandle': 'AQEBM2hLGIzgTIL3ys1umphdZRJqBj8jVqsX1psWwUm+aBJSAt7Prj6JLSJxPYbe0j8kxcuYhgsfQ5Q6PuOrguryFdOw1I5vvZqTpEpt6mHQvKvSG+DuIIJtatvg5J3LLVhDL6zITYpV9bwTM5gBoTybNSGRMsmWCRKlNIqY+sJ0S1XxSowsNRAY5a39eMs/SXFNqalr9tiTMdE4HJM3kXnB+5WvaS3bf1+Q49f/YJKHoDouUbeSnUavXK9STW4zM2DZGutd1Hnb7EwFpjagSK2MdEgEXQsS5ZxXPZYLH5GEcTPalx/9c5j9J2LjHwBHAo8xxrJtvdPvzEwXsJCNUzi1OD2yIl4ZgfrCK5XFmkDqKuLdsE4K4yQKwyxHro5tK59I', 'body': '{"Records":[{"eventVersion":"2.1","eventSource":"aws:s3","awsRegion":"eu-west-1","eventTime":"2021-01-06T15:02:04.774Z","eventName":"ObjectCreated:Put","userIdentity":{"principalId":"AWS:AROA5KZSFIYWCAWYR7Y5H:GreenGrassSession"},"requestParameters":{"sourceIPAddress":"54.195.165.65"},"responseElements":{"x-amz-request-id":"3E64A15AF01B30CC","x-amz-id-2":"5csXXXu0+UKoVPzu0eVPh42svenM/w6nft8cASqzdxVQKS363qLqDozt4ovmbRsgnhlrfwRCyYUuk45ECsbVOdGnLIxCZXiY"},"s3":{"s3SchemaVersion":"1.0","configurationId":"NewLogsZip","bucket":{"name":"logsplc-tmoullec","ownerIdentity":{"principalId":"A3JDWK0ZP4NRXW"},"arn":"arn:aws:s3:::logsplc-tmoullec"},"object":{"key":"log-1609945328.76.zip","size":566,"eTag":"4c89d535303bf10c712cc9e2b7baaf29","sequencer":"005FF5D0F0D0B32E39"}}}]}', 'attributes': {'ApproximateReceiveCount': '1', 'SentTimestamp': '1609945329749', 'SenderId': 'AIDAJQOC3SADRY5PEMBNW', 'ApproximateFirstReceiveTimestamp': '1609945329761'}, 'messageAttributes': {}, 'md5OfBody': 'e686b80d8cfef8295356968430288a6e', 'eventSource': 'aws:sqs', 'eventSourceARN': 'arn:aws:sqs:eu-west-1:916543850028:logsPLC', 'awsRegion': 'eu-west-1'}]}

    # 1- Parse File name
    log_file_name = get_log_file_name(event)
    
    print("Log Zip File Name:")
    print(log_file_name)
    
    # 2- Download file from S3
    download_path = "/tmp/"+log_file_name
    s3_client.download_file(logs_bucket, log_file_name, download_path)
    s3_file = download_path
    
    print("S3 file downloaded:")
    print(s3_file)
    
    # 3- Retrieve DynamoDB Item with the GG_UID and zip file name
    DDB_item = get_ddb_item(log_file_name)
    print("DDB Item Fetched")
    print(DDB_item)
    
    # 4- compare with DDB item hash
    similarity = compare_hashes(s3_file, DDB_item['zipHash'])
    if similarity:
        print("Zip Hashes are Similar!")
        # 5- Unzip file and calculate hashes of files and compare with DDB
        # TO DO: If checking zip files is useful - Need to setup a return check on check_zip_artifacts(s3_file, DDB_item)
        check_zip_artifacts(s3_file, DDB_item)
        return {
            'statusCode': 200,
            'body': json.dumps('Log Tamper Proof OK')
        }
    else:
        print("Hashes are Different!")
        # 6- If any hash is different, Send notification with SNS
        notify_mismatch_hash(DDB_item['zipHash'], s3_file)
        return {
            'statusCode': 200,
            'body': json.dumps('Hashes are different, Administrator has been notified.')
        }