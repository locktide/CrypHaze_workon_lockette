<?php
// Distributed Web Generation.

include "wtconfig.php";
include "GRTTableHeaders.php";

// How many chains to generate at a time.
$generateNumberChains = 100000;

if (isset($_POST['readTableHeader']) && ($_POST['readTableHeader'] == 'generate')) {
    $GRTTableHeader = new GRTTableHeaderBuilder();


    $GRTTableHeader->setTableVersion(3);
    $GRTTableHeader->setHashVersion(1);
    $GRTTableHeader->setHashString("MD5");
    $GRTTableHeader->setTableIndex(0);
    $GRTTableHeader->setChainLength(1000);
    $GRTTableHeader->setNumberChains($generateNumberChains);
    $GRTTableHeader->setPasswordLength(8);

    // Charset stuff
    $charset = "abcdefghijklmnopqrstuvwxyz";
    $GRTTableHeader->setCharsetCount(1);
    $GRTTableHeader->setSingleCharsetLength(strlen($charset));
    $GRTTableHeader->setSingleCharset($charset);
    $GRTTableHeader->setBitsInPassword(0);
    $GRTTableHeader->setBitsInHash(128);

    // Get a random seed value.
    $tableSeedValue = mt_rand(0, 0xffffffff);
    $GRTTableHeader->setRandomSeedValue($tableSeedValue);

    // Set a somewhat random chain start offset.
    $chainStartOffset = mt_rand(0, 100000);
    $GRTTableHeader->setChainStartOffset($chainStartOffset);

    $tableHeader = $GRTTableHeader->getTableHeaderString();

    if (strlen($tableHeader) != 8192) {
        exit;
    }
    ob_start();
    print $tableHeader;
    ob_flush();
    exit;
}


if (isset($_FILES['uploadFilename'])) {

    $uploadFilenameFullPath = $tableUploadPath . mt_rand(0x00, 0xffffffff) . basename($_FILES['uploadFilename']['name']);

    // Check to make sure it's actually an uploaded file
    if (is_uploaded_file($_FILES['uploadFilename']['tmp_name'])) {
        // Do stuff
        // Check 0.01% of chains
        $chainVerificationInterval = $generateNumberChains / 1000;
        $verifyCommand = $tableVerifyBinaryPath . " " . $_FILES['uploadFilename']['tmp_name'] . " 0 $chainVerificationInterval > /dev/null";
        //print "Verify command: " . $verifyCommand . "\n";
        system($verifyCommand, $verifyReturnValue);
        //print "return value: $verifyReturnValue\n";
        if ($verifyReturnValue == 0) {
            print "OK";
            move_uploaded_file($_FILES['uploadFilename']['tmp_name'], $uploadFilenameFullPath);
        } else {
            print "FAILURE: Uploaded file failed verification.\n";
        }
    } else {
        // Something weird happened.  Quit.
        print "FAILURE: Invalid uploaded file!\n";
        exit;
    }
}




?>