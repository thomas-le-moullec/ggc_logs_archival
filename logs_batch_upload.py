import json
from datetime import datetime
import time
import sys
import platform
import os
import logging
import hashlib
import boto3
from botocore.exceptions import ClientError
from boto3.s3.transfer import TransferConfig
from zipfile import ZipFile
from decimal import Decimal

# Config
topic_for_msg_forwarding = "data/batch_upload"

# JSON keys for output
DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f%Z"

# DynamoDB
dynamodb = boto3.resource("dynamodb", region_name="eu-west-1")
tableName = "LogsPLC"
GG_UID = 42

#S3
s3_client = boto3.client('s3', region_name="eu-west-1")
logsBucket = "logsplc-tmoullec"
# Set the desired multipart threshold value (5GB)
GB = 1024 ** 3
config = TransferConfig(multipart_threshold=5*GB)

# We need to be able to add files to the greengrass (Maybe use the Volume resources to access /tmp)- We can create file and add the timestamp in it
# We will leverage the md5-content header in S3 to check the zip file
# We will calculate the md5 for the zip and for individual files
# We will enter each individual md5 checksum in DynamoDB
# on upload we will trigger a lambda function that will unzip and check each this hashes
    
# Setup logging to stdout
logger = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

volumePath = '/dest/LRAtest'
localResourceAccessTopic = 'LRA/test'

# END of config

# Create a Greengrass Core SDK client.
try:
    import greengrasssdk
    client = greengrasssdk.client('iot-data')
    host = "ggc"
    logger.info('HOST GGC')
except Exception as e:
    client = boto3.client('iot-data', region_name='eu-west-1')
    host = "linux"
    logger.info('HOST Linux')

def timestampToDateTime(timestamp):
    return datetime.utcfromtimestamp(timestamp)
    
def timestampToString(timestamp, outFormat=DATETIME_FORMAT):
    return timestampToDateTime(timestamp=timestamp).strftime(outFormat)
    
def ackBatchUploadRequest():
    client.publish(topic=localResourceAccessTopic, payload='Sent from AWS IoT Greengrass Core.')
    volumeInfo = os.stat(volumePath)
    client.publish(topic=localResourceAccessTopic, payload=str(volumeInfo))
    logger.info('ACK DONE')
    
def updateFile(batchStartTime):
    with open(volumePath + '/test', 'a') as output:
        BatchTime = timestampToString(timestamp=batchStartTime, outFormat=DATETIME_FORMAT)
        output.write('Successfully write to test file at '+BatchTime+'\n')

def notifyFileContent():
    with open(volumePath + '/test', 'r') as myfile:
        data = myfile.read()
    client.publish(topic=localResourceAccessTopic, payload=data)

# SHA 256 hashing algorithm is widely used in security applications and protocols. The following python program computes the SHA256 hash value of a file. Note that the computed hash is converted to a readable hexadecimal string
def calculateHash(filename):
    with open(filename,"rb") as f:
        bytes = f.read() # read entire file as bytes
        readable_hash = hashlib.sha256(bytes).hexdigest();
        return(readable_hash)
        
def zipFiles(pathname, zipFilename):
    print('Zipping Files - pathname: '+pathname)
    print('Zipping Files - zipFilename: '+zipFilename)
    # Create a ZipFile Object
    with ZipFile(pathname+zipFilename, 'w') as zipObj:
       # Add multiple files to the zip
       zipObj.write(pathname+'test')

def insertChecksumDDB(batchStartTime, zipFilename, readable_hash_zip, filesHashes):
    global tableName
    table = dynamodb.Table(tableName)
    table.put_item(
        Item={
            "GG_ID": str(GG_UID),
            "timestamp": batchStartTime,
            "zipFilename": zipFilename,
            "zipHash": readable_hash_zip,
            "filesHashes": filesHashes
        }
    )
    return

def prepareBatch(batchStartTime):
    # zip files && calculate checksum && insert in DynamoDB table
    readable_hash = calculateHash(volumePath + '/test')
    print('readable_hash:' + readable_hash)
    zipFilename = 'log-'+str(batchStartTime)+'.zip'
    print('zipFilename: '+zipFilename)
    zipFiles(volumePath+'/', zipFilename)
    readable_hash_zip = calculateHash(volumePath +'/'+ zipFilename)
    print('readable_hash_zip: ' + readable_hash_zip)
    insertChecksumDDB(str(batchStartTime), zipFilename, readable_hash_zip, readable_hash)
    return zipFilename
    
# upload in S3
def uploadBatch(fileName, bucket, objectName=None):
    # If S3 object_name was not specified, use file_name
    if objectName is None:
        objectName = fileName
    try:
        response = s3_client.upload_file(
            fileName, bucket, objectName, Config=config
        )
    except ClientError as e:
        logging.error(e)
        return False
    return True

def function_handler(event, context):
    try:
        batchStartTime = int(round(time.time() * 1000))
        logger.info('Start Time: '+str(batchStartTime))
        ackBatchUploadRequest()
        updateFile(batchStartTime)
        notifyFileContent()
        zipFilename = prepareBatch(batchStartTime)
        uploadBatch(volumePath +'/'+ zipFilename, logsBucket, zipFilename)
    except Exception as e:
        logger.info('Failed to publish message: ' + repr(e))
    return

if host == 'linux':
    volumePath = '/src/LRAtest'
    function_handler('event', 'content')