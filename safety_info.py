def return_sensitive2(file_url):
    sensitive_data = {
        file_url: {
            "x_username": "username_1234",
            "x_password": "password_1234",
            "x_pin": "4321",
            "x_email": "my_email_123@example.com",
            "x_first_name" : "Mclovin",
            "x_last_name" : "Muhammad",
            "x_best_friend" : "fogell",
            "x_pet_name" : "buddy",
            "x_credit_card_number" : "1234 5555 4321 1111",
            "x_file_path" : "/home/disk/file.txt"
            }
        }
    return sensitive_data
 
def return_sensitive(file_url):
    sensitive_data = {
        file_url: {
            "x_username": "username_1234",
            "x_password": "password_1234",
            "x_pin": "4321",
            "x_email": "my_email_123@example.com",
            "first name" : "Mclovin",
            "last name" : "Muhammad",
            "gender" : "Male",
            "Best Friend" :"fogell",
            
            #ID&Passwords
            "dropbox_id": "username_dropbox_1234",
            "dropbox_password": "password_dropbox_1234",
            "google_id": "username_google_1234",
            "google_password": "password_google_1234",

            # Banking sites
            "chase_id": "username_chase_1234",
            "chase_password": "password_chase_1234",
            "wells_fargo_id": "username_wellsfargo_1234",
            "wells_fargo_password": "password_wellsfargo_1234",
            "citi_id": "username_citi_1234",
            "citi_password": "password_citi_1234",
            "bank_of_america_id": "username_bofa_1234",
            "bank_of_america_password": "password_bofa_1234",
            "hsbc_id": "username_hsbc_1234",
            "hsbc_password": "password_hsbc_1234",

            # Shopping sites
            "amazon_id": "username_amazon_1234",
            "amazon_password": "password_amazon_1234",
            "ebay_id": "username_ebay_1234",
            "ebay_password": "password_ebay_1234",
            "etsy_id": "username_etsy_1234",
            "etsy_password": "password_etsy_1234",
            "walmart_id": "username_walmart_1234",
            "walmart_password": "password_walmart_1234",
            "alibaba_id": "username_alibaba_1234",
            "alibaba_password": "password_alibaba_1234",
            "shopify_id": "username_shopify_1234",
            "shopify_password": "password_shopify_1234",
            "facebook_id": "username_facebook_1234",
            "facebook_password": "password_facebook_1234",
            "twitter_id": "username_twitter_1234",
            "twitter_password": "password_twitter_1234",
            "instagram_id": "username_instagram_1234",
            "instagram_password": "password_instagram_1234",
            "linkedin_id": "username_linkedin_1234",
            "linkedin_password": "password_linkedin_1234",
            "github_username": "username_github_1234",
            "github_password": "password_github_1234",
            "slack_username": "username_slack_1234",
            "slack_password": "password_slack_1234",
            "discord_id": "username_discord_1234",
            "discord_password": "password_discord_1234",
            "email_username": "user@example.com",
            "email_password": "email_pass_1234",
            "bank_id": "bank_user_1234",
            "bank_password": "bank_pass_1234",
            "paypal_id": "paypal_user_1234",
            "paypal_password": "paypal_pass_1234",
            "vpn_username": "vpn_user_1234",
            "vpn_password": "vpn_pass_1234",
            "ftp_username": "ftp_user_1234",
            "ftp_password": "ftp_pass_1234",
            "database_username": "db_user_1234",
            "database_password": "db_pass_1234",
            "ssh_username": "ssh_user_1234",
            "ssh_password": "ssh_pass_1234",
            "Other Id" : "ID_1234",
            "Other PASSWORDs" : "password",

            # Security questions
            "x_security_question_favorite_book": "favorite_book",
            "x_security_answer_favorite_book": "1984",
            "x_security_question_favorite_movie": "favorite_movie",
            "x_security_answer_favorite_movie": "Inception",
            "x_security_question_first_pet": "first_pet_name",
            "x_security_answer_first_pet": "Buddy",
            "x_security_question_first_school": "first_school_name",
            "x_security_answer_first_school": "Lincoln High",
            "x_security_question_favorite_teacher": "favorite_teacher",
            "x_security_answer_favorite_teacher": "Ms. Johnson",

            # Authentication tokens & API keys
            "x_two_factor_secret": "JBSWY3DPEHPK1234",
            "x_api_key": "APIKEY1234567890",
            "x_oauth_token": "oauth_tok_xyz987654",
            "x_session_token": "session_tok_abcdef123456",

            # Financial info
            "x_bank_account_number": "0123456789",
            "x_routing_number": "987654321",
            "x_credit_card_number": "4111 1111 1111 1111",
            "x_credit_card_expiry": "12/34",
            "x_credit_card_cvv": "123",
            "x_swift_code": "ABCDUS33",

            # Personal identifiers
            "x_ssn": "123-45-6789",
            "x_tax_id": "98-7654321",
            "x_passport_number": "P12345678",
            "x_driver_license": "D87654321",
            "x_insurance_policy_number": "INS-000123456",

            # Contact & recovery
            "x_recovery_email": "recovery@example.com",
            "x_phone_number": "+1-555-0123",
            "x_recovery_phone": "+1-555-9999",
            "x_address": "1234 Main St, Anytown, USA",
            "x_gps_coordinates": "37.1234,127.9876",

            # Device & network
            "x_mac_address": "00:1A:2B:3C:4D:5E",
            "x_ip_address": "192.168.1.100",
            "x_device_fingerprint": "fp_hash_abcdef123456",

            # Biometric & IDs
            "x_biometric_template_path": "/home/user/biometrics/template.dat",
            "x_face_id_template": "/home/user/biometrics/face_id.dat",
            "x_fingerprint_template": "/home/user/biometrics/fingerprint.dat",
            "x_id_card_path": "/home/user/docs/id_card.png",
            "x_profile_picture_path": "/home/user/photos/profile.jpg",

            # SSH & certificates
            "x_ssh_public_key_path": "/home/user/.ssh/id_rsa.pub",
            "x_ssh_private_key_path": "/home/user/.ssh/id_rsa",
            "x_ssl_certificate_path": "/home/user/certs/cert.pem",
            "x_ssl_private_key_path": "/home/user/certs/key.pem",

            # Backup & storage
            "x_file_backup_location": "/mnt/backup/important_docs/",
            "x_document_archive_path": "/mnt/archive/docs.zip",

            # VPN & Wi-Fi
            "vpn_user": "vpn_user_01",
            "vpn_pass": "vpn_pass_01",
            
            "x_wifi_ssid": "MyHomeWiFi",
            "x_wifi_password": "homewifi123",

            # 2FA & hardware tokens
            "authy_id": "authy_abc123",
            "hardware_token_serial": "TOKEN123456",

            # Loyalty & membership
            "x_loyalty_card_number": "LOYALTY-7890",
            "x_loyalty_card_pin": "4321",
            "x_member_id": "M123456",
            "gift_card_number" : "gift_1234",
            
            "Game_id" : "game_id_1234",
            "Game_password" : "game_password_1234",

            

            # Employment & education IDs
            "x_employee_id": "E987654",
            "x_student_id": "S123456",

            # Cryptocurrency wallets
            "bitcoin": "1q2w3e4r5t6y7u8i9o0p12341234abcd",
            "ethereum": "0xAbC1234567890DefABC1234567890dEFabC12345",
        }
    }
    return sensitive_data

