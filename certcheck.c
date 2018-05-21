/* 
 * COMP30023 Computer Systems
 * Semester 1, 2018
 * Assignment 2 - Certificate Validation using OpenSSL
 *
 * Name: Emmanuel Macario <macarioe@student.unimelb.edu.au>
 * Student Number: 831659
 * Last Modified: 21/05/18
 */
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>


#define MAX_LENGTH 1000
#define BC_DEFAULT "CA:FALSE"
#define EKU_DEFAULT "TLS Web Server Authentication"
#define RSA_KEYSIZE_DEFAULT 2048


void usage_exit(char *prog_name) {
    printf("Usage: %s [path to csv file]\n", prog_name);
    exit(EXIT_FAILURE);
}


bool validate_rsa_key_size(X509 *cert) {

    // Get size of public key modulus in bits.
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    int key_type = EVP_PKEY_type(pkey->type);
    assert(key_type == EVP_PKEY_RSA);

    int keysize = BN_num_bits(pkey->pkey.rsa->n);
    EVP_PKEY_free(pkey);

    if (keysize == RSA_KEYSIZE_DEFAULT) {
        return true;
    }
    return false;
}


bool validate_not_before(X509 *cert) {
    int day, sec;

    ASN1_TIME *not_before = X509_get_notBefore(cert);
    ASN1_TIME_diff(&day, &sec, not_before, NULL);

    if (sec > 0 || day > 0) {
        return true;
    }
    return false;
}


bool validate_not_after(X509 *cert) {
    int day, sec;

    ASN1_TIME *not_after = X509_get_notAfter(cert);
    ASN1_TIME_diff(&day, &sec, NULL, not_after);

    if (sec > 0 || day > 0) {
        return true;
    }
    return false;
}


bool validate_dates(X509 *cert) {
    return validate_not_before(cert) && validate_not_after(cert);
}


bool hostmatch(char *domain_name, char *pattern) {
    assert(domain_name != NULL && pattern != NULL);

    char *pattern_wildcard, *pattern_label_end, *domain_name_label_end;

    // If no wildcard, just if they are the same.
    pattern_wildcard = strchr(pattern, '*');
    if (pattern_wildcard == NULL) {
        return !strcasecmp(domain_name, pattern) ? true : false;
    }

    // Ensure at minimum two periods are present in pattern to avoid 'too wide'
    // wildcard domains.
    // i.e. A cert with '*' plus a TLD is not allowed (e.g. '*.com').
    //      A cert with just '*' is too general and is not allowed.
    pattern_label_end = strchr(pattern, '.');
    if (pattern_label_end == NULL || 
        strchr(pattern_label_end + 1, '.') == NULL) {
        return false;
    }

    // Make sure that the wildcard matches at least one character.
    domain_name_label_end = strchr(domain_name, '.');
    if (domain_name_label_end - domain_name < pattern_label_end - pattern) {
        return false;
    }

    // Now, check if the domain name matches the pattern. Ensures that
    // only a single level of subdomain matching is supported. This is because
    // the wildcard only covers one level of subdomains.
    if (domain_name_label_end == NULL ||
        strcasecmp(domain_name_label_end, pattern_label_end)) {
        return false;
    }

    // If all checks passed, we have a match!
    return true;
}



bool matches_common_name(char *domain_name, X509 *cert) {

    X509_NAME *subject = X509_get_subject_name(cert);

    // Find position of CN field in the Subject field of certificate.
    int common_name_index = 
                X509_NAME_get_index_by_NID(subject, NID_commonName, -1);

    if (common_name_index < 0) {
        fprintf(stderr, "Unable to find location of CN in Subject field\n");
        exit(EXIT_FAILURE);
    }

    // Extract the CN field entry.
    X509_NAME_ENTRY *common_name_entry 
                    = X509_NAME_get_entry(subject, common_name_index);

    if (common_name_entry == NULL) {
        fprintf(stderr, "Unable to extract CN entry from Subject field\n");
        exit(EXIT_FAILURE);
    }

    // Convert CN field entry to an ASN1 encoded string.
    ASN1_STRING *common_name_asn1 = X509_NAME_ENTRY_get_data(common_name_entry);
    if (common_name_asn1 == NULL) {
        fprintf(stderr, "Unable to convert CN entry into ASN1 string\n");
        exit(EXIT_FAILURE);
    }

    // Convert the ASN1 encoded string into a C string.
    char *common_name = (char *)ASN1_STRING_data(common_name_asn1);
    if (common_name == NULL) {
        fprintf(stderr, "Unable to convert ASN1 string to C string\n");
        exit(EXIT_FAILURE);
    }

    return hostmatch(domain_name, common_name);
}


bool matches_subject_alt_name(char *domain_name, X509 *cert) {

    // Get the Subject Alternative Names (if they exist).
    STACK_OF(GENERAL_NAME) *sans =
                 X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);


    // If certificate does not contain SAN extension, just return false.
    if (sans == NULL) {
        return false;
    }

    int n_sans = sk_GENERAL_NAME_num(sans);

    // For each SAN, see if we get a match!
    bool match = false;
    for (int i = 0; i < n_sans; i++) {

        GENERAL_NAME *san = sk_GENERAL_NAME_value(sans, i);

        if (san->type == GEN_DNS) {
            // Current SAN is a DNS, need to check it.
            char *dns_name = (char *)ASN1_STRING_data(san->d.dNSName);
            
            if (hostmatch(domain_name, dns_name)) {
                match = true;
                break;
            }
        }
    }

    // Free the stack of SANs.
    sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);

    return match;
}


bool validate_domain_name(char *domain_name, X509 *cert) {
    assert(domain_name != NULL && cert != NULL);

    // First try to see if domain names matches CN.
    bool match = matches_common_name(domain_name, cert);

    // If domain name doesn't match CN, check for a match 
    // in SANs (only if certificate contains SAN extension).
    if (!match) {
        match = matches_subject_alt_name(domain_name, cert);
    }
    return match;
}



bool validate_basic_constraints(X509 *cert) {

    int index = X509_get_ext_by_NID(cert, NID_basic_constraints, -1);
    X509_EXTENSION *ex = X509_get_ext(cert, index);

    ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
    if (obj == NULL) {
        fprintf(stderr, "Unable to extract ASN1 object from extension");
    }

    BIO *ext_bio = BIO_new(BIO_s_mem());
    if (ext_bio == NULL) {
        fprintf(stderr, "Unable to allocate memory for extension value BIO");
    }

    if (!X509V3_EXT_print(ext_bio, ex, 0, 0)) {
        M_ASN1_OCTET_STRING_print(ext_bio, ex->value);
    }


    BUF_MEM *bptr = NULL;
    BIO_flush(ext_bio);
    BIO_get_mem_ptr(ext_bio, &bptr);

    char *data = (char *)malloc((bptr->length + 1) * sizeof(char));
    memcpy(data, bptr->data, bptr->length);
    data[bptr->length] = '\0';

    bool valid;
    if (strstr(data, BC_DEFAULT) == NULL) {
        valid = false;
    } else {
        valid = true;
    }

    BIO_free_all(ext_bio);
    free(data);

    return valid;
}



bool validate_ext_key_usage(X509 *cert) {

    int index = X509_get_ext_by_NID(cert, NID_ext_key_usage, -1);
    X509_EXTENSION *ex = X509_get_ext(cert, index);

    ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
    if (obj == NULL) {
        fprintf(stderr, "Unable to extract ASN1 object from extension\n");
    }

    BIO *ext_bio = BIO_new(BIO_s_mem());
    if (ext_bio == NULL) {
        fprintf(stderr, "Unable to allocate memory for extension value BIO\n");
    }

    if (!X509V3_EXT_print(ext_bio, ex, 0, 0)) {
        M_ASN1_OCTET_STRING_print(ext_bio, ex->value);
    }

    BUF_MEM *bptr = NULL;
    BIO_flush(ext_bio);
    BIO_get_mem_ptr(ext_bio, &bptr);

    char *data = (char *)malloc((bptr->length + 1) * sizeof(char));
    memcpy(data, bptr->data, bptr->length);
    data[bptr->length] = '\0';

    bool valid;
    if (strstr(data, EKU_DEFAULT) == NULL) {
        valid = false;
    } else {
        valid = true;
    }

    BIO_free_all(ext_bio);
    free(data);

    return valid;
}


int validate_certificate(char *filename, char *domain_name) {

    BIO *certificate_bio = NULL;
    X509 *cert = NULL;

    // Create BIO object to read certificate.
    certificate_bio = BIO_new(BIO_s_file());

    // Read certificate into BIO.
    if (!(BIO_read_filename(certificate_bio, filename))) {
        fprintf(stderr, "Error in reading cert BIO filename\n");
        exit(EXIT_FAILURE);
    }
    if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL))) {
        fprintf(stderr, "Error in loading certificate\n");
        exit(EXIT_FAILURE);
    }

    // Validate or invalidate the certificate.
    bool valid = validate_dates(cert) &&
                 validate_domain_name(domain_name, cert) &&
                 validate_rsa_key_size(cert) &&
                 validate_basic_constraints(cert) &&
                 validate_ext_key_usage(cert);

    X509_free(cert);
    BIO_free_all(certificate_bio);

    return valid ? 1 : 0;
}


/** MAIN PROGRAM **/
int main(int argc, char *argv[]) {

    // Check command line arguments supplied.
    if (argc != 2) {
        usage_exit(argv[0]);
    }

    // Name of input csv file.
    char *input_csv = argv[1];

    // Try opening the input csv file.
    FILE *in = fopen(input_csv, "r");
    if (in == NULL) {
        fprintf(stderr, "Failed to open input csv file\n");
        exit(EXIT_FAILURE);
    }

    // Initialise OpenSSL.
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();


    // Get output file ready for writing into.
    FILE *out = fopen("output.csv", "w");
    if (out == NULL) {
        fprintf(stderr, "Error creating output file\n");
        exit(EXIT_FAILURE);
    }

    char filename[MAX_LENGTH], domain[MAX_LENGTH], line[MAX_LENGTH];


    // Parse and process each line of the input csv 
    // file one at a time.
    while (fgets(line, MAX_LENGTH, in) != NULL) {

        // Get certificate filename and the domain name.
        if (sscanf(line, "%[^,],%s\n", filename, domain) != 2) {
            fprintf(stderr, "Error reading in csv file\n");
            exit(EXIT_FAILURE);
        }

        // Check if the certificate is valid with respect to the domain name.
        int valid = validate_certificate(filename, domain);

        // Print result to the output file.
        fprintf(out, "%s,%s,%d\n", filename, domain, valid);
    }

    // Close the input file.
    fclose(in);

    // Close the output file.
    fclose(out);

    // Job done!
    exit(EXIT_SUCCESS);
}