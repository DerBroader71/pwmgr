#!/usr/bin/php
<?php
/**
* Password manager
*
* Stores sites, username and password. Each entry has a unique identifier
* Username and passwords are encrypted using a 2 part hash
*  - a key file created and stored at first run
*  - a passphrase entered when the program is run
* Decryption requires both parts rendering the stored information useless
*
* PHP 5.3+
*
* Release under The Unlicense
*/

// prompt for the passphrase to be used as a salt for the encryption - passphrase + key for encryption and decryption
echo 'Enter passphrase: ';
hide_term();
$passphrase = rtrim(fgets(STDIN), PHP_EOL);
restore_term();
// then hash it so that it gets passed around the functions in a reasonably secure format and not blurted out in plain text in an error
$passphrase = hash('sha256', $passphrase);

// check to see if key has been generated, if not - generate one and then create database
$key_file = "./.pwmgr.key";
if (!file_exists($key_file)) {
        // generate the key file
        generateKey($key_file);
        // create the database table and unique index
        try {
                $dbh = new PDO('sqlite:./pwmgr.sqlite3');
                $dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                $dbh->exec("CREATE TABLE IF NOT EXISTS passwords (
                                        id INTEGER PRIMARY KEY,
                                        uuid TEXT,
                                        site TEXT,
                                        encuser TEXT,
                                        encpass TEXT)");
                $dbh->exec("CREATE UNIQUE INDEX uuid ON passwords (uuid)");
        } catch (PDOException $e) {
                echo 'Database error: ' . $e->getMessage();
        }
}

while( true ) {
        printMenu();

        $choice = trim( fgets(STDIN) );

        if( $choice == 5 || $choice === 'q' || $choice === 'Q') {
                break;
        }

        switch( $choice ) {
                case 1:
                {
                        addEntry($passphrase);
                        break;
                }
                case 2:
                {
                        searchEntries($passphrase);
                        break;
                }
                case 3:
                {
                        removeEntry($passphrase);
                        break;
                }
                case 4:
                {
                        listEntries($passphrase);
                        break;
                }
                default:
                {
                        echo "\n\nInvalid option. Please try again.\n\n";
                }
        }
}

function printMenu() {
        // get the count of current entries
        $dbh = dbhandler();
        try {
                $sth = $dbh->prepare("SELECT COUNT(id) AS total FROM passwords");
                $sth->execute();
                $result = $sth->fetch(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
                echo 'Database error: ' . $e->getMessage();
                return;
        }

        echo "************ Password Manager ******************\n";
        echo $result['total']." entries\n";
        echo "1 - Add Entry\n";
        echo "2 - Search Entries\n";
        echo "3 - Remove Entry\n";
        echo "4 - List all Entries\n";
        echo "5 - Exit\n";
        echo "************ Password Manager  ******************\n";
        echo "Enter your choice from 1 to 5 ::";
}

function addEntry($passphrase) {
        // get the input
        $site = readline("Site: ");
        $user = readline("User: ");
        echo "Password: ";
        hide_term();
        $password = rtrim(fgets(STDIN), PHP_EOL);
        restore_term();
        echo "Confirm Password: ";
        hide_term();
        $password2 = rtrim(fgets(STDIN), PHP_EOL);
        restore_term();
        if ($password != $password2) {
                // passwords don't match
                echo "Passwords don't match!\n";
                $line = readline("Press Enter to continue...");
                return;
        } else {
                // generate the UUID
                $uuid = guidv4(openssl_random_pseudo_bytes(16));

                // encrypt the usernames and passwords and unset the old ones
                $enc_user = base64_encode(encryptData($passphrase, $user));
                unset ($user); // remove the original data
                $enc_password = base64_encode(encryptData($passphrase, $password));
                unset ($password); // remove the original data
                unset ($password2); // remove the original confirmation data

                // insert it into the database
                try {
                        $dbh = dbhandler();
                        $sth = $dbh->prepare("INSERT INTO passwords (uuid, site, encuser, encpass) VALUES (:uuid, :site, :enc_user, :enc_password)");
                        $sth->bindParam(':uuid', $uuid);
                        $sth->bindParam(':site', $site);
                        $sth->bindParam(':enc_user', $enc_user);
                        $sth->bindParam(':enc_password', $enc_password);
                        $sth->execute();
                } catch (PDOException $e) {
                        echo 'Database error: ' . $e->getMessage();
                        return;
                }
        }
}

function searchEntries($passphrase) {
        // get the input
        $input = readline("Enter site to search for: ");
        $input = '%'.$input.'%';

        // search the database
        $dbh = dbhandler();
        try {
                $sth = $dbh->prepare("SELECT * FROM passwords WHERE site LIKE :site");
                $sth->bindParam(':site', $input);
                $sth->execute();
                $result = $sth->fetchAll(PDO::FETCH_ASSOC);
                // print the results
                echo "************ Password Details ******************\n";
                foreach ($result as $row) {
                        echo "UUID: ".$row['uuid']."\n";
                        echo "Site: ".$row['site']."\n";
                        echo "User: ".decryptData($passphrase, base64_decode($row['encuser']))."\n";
                        echo "Password: ".decryptData($passphrase, base64_decode($row['encpass']))."\n\n";
                        echo "------------------------------------------------\n";
                }
                echo "************************************************\n";
        } catch (PDOException $e) {
                echo 'Database error: ' . $e->getMessage();
                return;
        }
}

function removeEntry($passphrase) {
        // get the input
        $input = readline("Enter UUID to remove: ");

        // get details from the database
        $dbh = dbhandler();
        try {
                $sth = $dbh->prepare("SELECT * FROM passwords WHERE uuid = :uuid LIMIT 1");
                $sth->bindParam(':uuid', $input);
                $sth->execute();
                $result = $sth->fetch(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
                echo 'Database error: ' . $e->getMessage();
                return;
        }
        if ($result['uuid'] === '' || is_null($result['uuid'])) {
                return;
        }
        echo "UUID: ".$result['uuid']."\n";
        echo "Site: ".$result['site']."\n";
        echo "User: ".decryptData($passphrase, base64_decode($result['encuser']))."\n";
        echo "Password: ".decryptData($passphrase, base64_decode($result['encpass']))."\n\n";
        if (ask_YN("Remove this entry?")) {
                // it returned true (yes)
                try {
                        $sth = $dbh->prepare("DELETE FROM passwords WHERE uuid = :uuid");
                        $sth->bindParam(':uuid', $result['uuid']);
                        $sth->execute();
                        echo "Entry deleted";
                } catch (PDOException $e) {
                        echo 'Database error: ' . $e->getMessage();
                        return;
                }
        } else {
                // it returned false (no)
                return;
        }
}

function listEntries($passphrase) {
        // get details from the database
        $dbh = dbhandler();
        try {
                $sth = $dbh->prepare("SELECT * FROM passwords");
                $sth->execute();
                $result = $sth->fetchAll(PDO::FETCH_ASSOC);
                echo "************ Password Details ******************\n";
                foreach ($result as $row) {
                        echo "UUID: ".$row['uuid']."\n";
                        echo "Site: ".$row['site']."\n";
                        echo "User: ".decryptData($passphrase, base64_decode($row['encuser']))."\n";
                        echo "Password: ".decryptData($passphrase, base64_decode($row['encpass']))."\n\n";
                        echo "------------------------------------------------\n";
                }
                echo "************************************************\n";
        } catch (PDOException $e) {
                echo 'Database error: ' . $e->getMessage();
                return;
        }
}

function generateKey($filename, $algo = 'sha256', $length = 1024) {
        $key = '';
        // do it via openssl or /dev/urandom
        if ( function_exists('openssl_random_pseudo_bytes') ) {
                $data = openssl_random_pseudo_bytes($length, $cstrong) . mt_rand() . microtime();
                $key = hash($algo, $data);
        } else {
                $data = mt_rand() . microtime() . file_get_contents('/dev/urandom', $length) . mt_rand() . microtime();
                $key = hash($algo, $data);
        }
        file_put_contents($filename, $key);
}

function decryptData($passphrase, $ciphertext) {
        // read the key
        $key_file = "./.pwmgr.key";
        $key = file_get_contents($key_file);
        $key = hash('sha256', $passphrase.$key);

        $c = base64_decode($ciphertext);
        $ivlen = openssl_cipher_iv_length($cipher="AES-128-CBC");
        $iv = substr($c, 0, $ivlen);
        $hmac = substr($c, $ivlen, $sha2len=32);
        $ciphertext_raw = substr($c, $ivlen+$sha2len);
        $plaintext = openssl_decrypt($ciphertext_raw, $cipher, $key, $options=OPENSSL_RAW_DATA, $iv);
        return $plaintext;
}

function encryptData($passphrase, $data) {
        // read the key
        $key_file = "./.pwmgr.key";
        $key = file_get_contents($key_file);
        $key = hash('sha256', $passphrase.$key);

        $ivlen = openssl_cipher_iv_length($cipher="AES-128-CBC");
        $iv = openssl_random_pseudo_bytes($ivlen);
        $ciphertext_raw = openssl_encrypt($data, $cipher, $key, $options=OPENSSL_RAW_DATA, $iv);
        $hmac = hash_hmac('sha256', $ciphertext_raw, $key, $as_binary=true);
        $ciphertext = base64_encode( $iv.$hmac.$ciphertext_raw );
        return $ciphertext;
}

function hide_term() {
        if (strtoupper(substr(PHP_OS, 0, 3)) !== 'WIN') {
                echo "\033[30;40m";
                flush();
        }
}

function restore_term() {
        if (strtoupper(substr(PHP_OS, 0, 3)) !== 'WIN') {
                echo "\033[0m";
                flush();
        }
}

function dbhandler() {
        try {
                $dbh = new PDO('sqlite:./pwmgr.sqlite3');
                $dbh->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch (PDOException $e) {
    echo 'Connection failed: ' . $e->getMessage();
        }
        return $dbh;
}

function ask_YN($prompt = '', $default = null) {
        if (is_null($default)) $default = false;
        if (strlen($prompt) > 0) $prompt .= ' ';
        $prompt .= ($default ? '[Y/n] ' : '[y/N] ');
        while (true) {
                print $prompt;
                $in = chop(fgets(STDIN));
                if ($in == '') return $default;
                if ($in == 'Y' || $in == 'y') return true;
                if ($in == 'N' || $in == 'n') return false;
        }
}

function guidv4($data) {
        assert(strlen($data) == 16);
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // set version to 0100
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // set bits 6-7 to 10
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}
