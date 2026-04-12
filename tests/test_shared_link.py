import os
import sys
import hashlib
import httpx
import logging
from mega import Mega

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

MEGA_EMAIL = "your_email@example.com"
MEGA_PASSWORD = "your_password"

def sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def main():
    try:
        logger.info("Logging in")
        m = Mega().login(MEGA_EMAIL, MEGA_PASSWORD)
        
        logger.info("Fetching target file")
        test_file = "test_video_verify.mp4"
        with httpx.stream("GET", "https://samplelib.com/mp4/sample-30s.mp4", follow_redirects=True) as r:
            with open(test_file, "wb") as f:
                for chunk in r.iter_bytes(): f.write(chunk)
                
        original_hash = sha256(test_file)

        logger.info("Uploading and linking")
        upload_result = m.upload(test_file)
        link = m.get_upload_link(upload_result)
        
        logger.info("Downloading shared link")
        download_path = "test_video_downloaded.mp4"
        m.download_url(link, dest_path='.', dest_filename=download_path)
        
        downloaded_hash = sha256(download_path)

        logger.info("Verifying match")
        assert original_hash == downloaded_hash, "Decrypted downloaded hash does not match original."
            
        logger.info("Cleaning up")
        os.remove(test_file)
        os.remove(download_path)
        m.destroy(upload_result['f'][0]['h'])
        
        logger.info("Match succeeded")

    except Exception as e:
        print(f"Error during testing: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
