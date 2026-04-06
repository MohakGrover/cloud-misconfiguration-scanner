import boto3
import sys
import datetime
# --- CONFIGURATION ---
TAG_KEY = "ScannerLab"
# Safe guard: Only nuke resources in this specific region to avoid accidents
SAFE_REGION = "us-east-2" 

def nuke_lab_resources():
    """
    Forcefully deletes any AWS resource tagged with 'ScannerLab'.
    This is a safety mechanism to prevent billing accidents.
    """
    print(f"⚠️  INITIATING NUKE PROTOCOL FOR REGION: {SAFE_REGION}")
    print(f"⚠️  Targeting resources with tag: {TAG_KEY}")
    
    confirm = input("Are you sure you want to delete all Lab resources? (yes/no): ")
    if confirm.lower() != "yes":
        print("Aborted.")
        return

    session = boto3.Session(region_name=SAFE_REGION)
    
    # 1. Nuke EC2 Instances
    ec2 = session.resource('ec2')
    instances = ec2.instances.filter(Filters=[{'Name': f'tag:{TAG_KEY}', 'Values': ['*']}])
    
    instance_ids = [i.id for i in instances]
    if instance_ids:
        print(f"💥 Terminating {len(instance_ids)} EC2 instances: {instance_ids}")
        ec2.instances.filter(InstanceIds=instance_ids).terminate()
    else:
        print("✅ No Lab instances found.")

    # 2. Nuke S3 Buckets
    s3 = session.resource('s3')
    # S3 tagging filtering is client-side for "list_buckets", so we iterate.
    # Note: Logic simplified for MVP. In prod, use ResourceGroupsTaggingAPI.
    for bucket in s3.buckets.all():
        try:
            tags = session.client('s3').get_bucket_tagging(Bucket=bucket.name).get('TagSet', [])
            is_lab = any(t['Key'] == TAG_KEY for t in tags)
            if is_lab:
                print(f"💥 Deleting bucket: {bucket.name}")
                # Must delete objects first
                bucket.objects.all().delete()
                bucket.delete()
        except:
            pass # No tags or permission issue

    print("\n✅ Nuke complete. Lab environment is clean.")

if __name__ == "__main__":
    nuke_lab_resources()