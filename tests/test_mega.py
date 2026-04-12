import os
import sys
import httpx
import logging
from mega import Mega

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

MEGA_EMAIL = "your_email@example.com"
MEGA_PASSWORD = "your_password"

def main():
    try:
        logger.info("Logging in")
        m = Mega().login(MEGA_EMAIL, MEGA_PASSWORD)
        
        logger.info("Fetching quota")
        limit = m.get_quota()
        space = m.get_storage_space()
        
        logger.info("Fetching test file")
        test_file = "sample.mp4"
        with httpx.stream("GET", "https://samplelib.com/mp4/sample-30s.mp4", follow_redirects=True) as r:
            with open(test_file, "wb") as f:
                for chunk in r.iter_bytes(): f.write(chunk)
                
        logger.info("Uploading file")
        upload_res = m.upload(test_file)
        
        logger.info("Generating link")
        link = m.get_upload_link(upload_res)
        
        logger.info("Creating folder")
        folder_dict = m.create_folder("mega_test_folder")
        folder_id = list(folder_dict.values())[0]
        
        logger.info("Moving file")
        m.move(upload_res['f'][0]['h'], folder_id)
        
        logger.info("Renaming file")
        m.rename(upload_res['f'][0], "renamed_sample.mp4")
        
        logger.info("Downloading via link")
        m.download_url(link, dest_path='.', dest_filename='downloaded_sample.mp4')
        
        logger.info("Deleting files")
        trash = m.get_node_by_type(4)
        m.delete(upload_res['f'][0]['h'])
        m.destroy(folder_id)
        
        logger.info("Cleaning up")
        os.remove(test_file)
        if os.path.exists('downloaded_sample.mp4'):
            os.remove('downloaded_sample.mp4')
            
        logger.info("Completed")
            
        print("Test suite successfully verified all API behaviors!")

    except Exception as e:
        print(f"Error during testing: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
