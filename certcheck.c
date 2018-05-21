#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

#include <stdbool.h>
#include <time.h>
#include <assert.h>
#include <inttypes.h>


#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509_vfy.h>

#include <ctype.h>


#define MAX_LENGTH 1024
#define DATE_LEN 128
#define EXTNAME_LEN 1024

#define BC_DEFAULT "CA:FALSE"
#define EKU_DEFAULT "TLS Web Server Authentication"
#define RSA_KEYSIZE_DEFAULT 2048

/* Functions cannot use:
X509_check_ca
X509_check_host
X509_cmp_current_time
X509_cmp_time
*/

/* To decode SSL X.509 certificates:
>> openssl x509 -in certificate.crt -text -noout > certificate-decoded.txt
*/

/*
TLS CERTIFICATES
1. CN - Common Name 
      - Should contain the DNS URL
      - Can contain only one URL
      - Can contain wildcards

2. SAN - Subject Alternative Names
       - Extension allows multiple URLs to be covered by a single certificate
       - Can contain wildcards
       - 4096 Kb size (approx. 150 DNS names)
*/


/* MINIMUM CHECKING FOR PROJECT
1. Validation of dates, both the Not Before and Not After dates
2. Domain name validation, including Subject Alternative Name (SAN) extensions and wildcards
3. Minimum key length of 2048 bits for RSA
4. Correct key usage, including extensions
*/


void usage_exit(char *prog_name) {
    printf("Usage: %s [path to csv file]\n", prog_name);
    exit(EXIT_FAILURE);
}


void print_certificate(X509 *cert) {
    char subj[MAX_LENGTH+1];
    char issuer[MAX_LENGTH+1];
    X509_NAME_oneline(X509_get_subject_name(cert), subj, MAX_LENGTH);
    X509_NAME_oneline(X509_get_issuer_name(cert), issuer, MAX_LENGTH);
    printf("Certificate: %s\n", subj);
    printf("\tIssuer: %s\n\n", issuer);
}


int convert_ASN1_TIME(ASN1_TIME *t, char *buf, size_t len) {
    int rc;

    BIO *b = BIO_new(BIO_s_mem());

    // Write date to bio.
    rc = ASN1_TIME_print(b, t);
    if (rc <= 0) {
        BIO_free(b);
        return EXIT_FAILURE;
    }
    // Write date from bio to buffer.
    rc = BIO_gets(b, buf, len);
    if (rc <= 0) {
        BIO_free(b);
        return EXIT_FAILURE;
    }
    BIO_free(b);
    return EXIT_SUCCESS;
}



bool validate_rsa_key_size(X509 *cert) {

    // Get size of public key modulus in bits.
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    int key_type = EVP_PKEY_type(pkey->type);
    assert(key_type == EVP_PKEY_RSA);

    int keysize = BN_num_bits(pkey->pkey.rsa->n);
    EVP_PKEY_free(pkey);

    // Print keysize for debugging.
    //printf("Key size = %d bits\n", keysize);

    if (keysize == RSA_KEYSIZE_DEFAULT) {
        //printf("RSA Key size PASSED\n\n");
        return true;
    }
    //printf("RSA Key size FAILED\n\n");
    return false;
}


bool validate_not_before(X509 *cert) {
    int day, sec;

    ASN1_TIME *not_before = X509_get_notBefore(cert);
    ASN1_TIME_diff(&day, &sec, not_before, NULL);

    // Note: if current time is after Not Before, then
    // one or both of sec and day will be positive.

    if (sec > 0 || day > 0) {
        //printf("Not Before PASSED\n");
        return true;
    }
    //printf("Not Before FAILED\n");
    return false;
}


bool validate_not_after(X509 *cert) {
    int day, sec;

    ASN1_TIME *not_after = X509_get_notAfter(cert);
    ASN1_TIME_diff(&day, &sec, NULL, not_after);

    // Note: if current time is before Not After, then
    // one or both of sec and day will be positive.

    if (sec > 0 || day > 0) {
        //printf("Not After PASSED\n");
        return true;
    }
    //printf("Not After FAILED\n");
    return false;
}


bool validate_dates(X509 *cert) {
    bool nb, na;
    nb = validate_not_before(cert);
    na = validate_not_after(cert);

    return nb && na;
}



bool raw_equals(const char *s1, const char *s2) {
    int c1, c2;

    while (*s1 && *s2) {
        // Convert characters to lowercase.
        c1 = tolower(*s1);
        c2 = tolower(*s2);

        // Compare characters.
        if (c1 != c2) {
            return false;
        }
        s1++;
        s2++;
    }
    // Do it again here, to make sure the strings are of same length.
    return *s1 == '\0' && *s2 == '\0';
}



bool hostmatch(char *domain_name, char *pattern) {
    char *pattern_wildcard;

    // If no wildcard, just if they are the same.
    pattern_wildcard = strchr(pattern, '*');
    if (pattern_wildcard == NULL) {
        return !strcasecmp(domain_name, pattern) ? true : false;
    }

    char *pattern_label_end, *domain_name_label_end;

    // Require at least 2 dots in pattern to avoid too wide wildcard domains.
    // i.e. A cert with '*' plus a TLD is not allowed (e.g. '*.com')
    //      A cert with just '*' is too general and is not allowed.
    pattern_label_end = strchr(pattern, '.');

    if (pattern_label_end == NULL || strchr(pattern_label_end+1, '.') == NULL) {
        return false;
    }

    // Make sure that the wildcard matches at least one character. Do this by
    // checking left-most label of the hostname is at least as large as the 
    // left-most label of the pattern. 
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

    // We have a match!
    return true;
}



bool matches_common_name(char *domain_name, X509 *cert) {

    // Get common name. Assume the certificate always has one.
    X509_NAME *subj = X509_get_subject_name(cert);

    // Find position of CN field in the Subject field of certificate.
    int cn_loc = X509_NAME_get_index_by_NID(subj, NID_commonName, -1);
    if (cn_loc < 0) {
        fprintf(stderr, "Unable to find location of CN in Subject field");
        exit(EXIT_FAILURE);
    }

    // Extract the CN field.
    X509_NAME_ENTRY *cn_entry = X509_NAME_get_entry(subj, cn_loc);
    if (cn_entry == NULL) {
        fprintf(stderr, "Unable to extract CN entry from Subject field");
        exit(EXIT_FAILURE);
    }

    // Convert CN field to a C string.
    ASN1_STRING *cn_asn1 = X509_NAME_ENTRY_get_data(cn_entry);
    if (cn_asn1 == NULL) {
        fprintf(stderr, "Unable to convert CN entry into ASN1 string");
        exit(EXIT_FAILURE);
    }

    char *cn = (char *)ASN1_STRING_data(cn_asn1);
    if (cn == NULL) {
        fprintf(stderr, "Unable to convert ASN1 string to C string");
        exit(EXIT_FAILURE);
    }

    return hostmatch(domain_name, cn);
}


bool matches_subject_alt_name(char *domain_name, X509 *cert) {
    
    STACK_OF(GENERAL_NAME) *sans = NULL;
    sans = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (sans == NULL) {
        return false;
    }

    int n_sans = sk_GENERAL_NAME_num(sans);
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

    // If it doesn't match CN, check for a match in SANs.
    // Note that the function to update 'match' returns false
    // if SAN extension does not exist within the certificate.
    if (!match) {
        match = matches_subject_alt_name(domain_name, cert);
    }
    return match;
}



bool validate_basic_constraints(X509 *cert) {
    // Get the index of the Basic Constraints extension in the stack of extensions.
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

    BUF_MEM *bptr;
    BIO_flush(ext_bio);
    BIO_get_mem_ptr(ext_bio, &bptr);
    BIO_set_close(ext_bio, BIO_NOCLOSE);
    BIO_free_all(ext_bio);


    char *data = (char *)malloc((bptr->length + 1) * sizeof(char));
    memcpy(data, bptr->data, bptr->length);
    data[bptr->length] = '\0';


    //printf("Basic Constraints: %s\n", data);

    if (strstr(data, BC_DEFAULT) == NULL) {
        free(data);
        return false;
        printf("Basic Constraints FAILED\n\n");
    } else {
        free(data);
        return true;
        printf("Basic Constraints PASSED\n\n");
    }
}



bool validate_ext_key_usage(X509 *cert) {

    int index = X509_get_ext_by_NID(cert, NID_ext_key_usage, -1);
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

    BUF_MEM *bptr;
    BIO_flush(ext_bio);
    BIO_get_mem_ptr(ext_bio, &bptr);
    BIO_set_close(ext_bio, BIO_NOCLOSE);
    BIO_free_all(ext_bio);


    char *data = (char *)malloc((bptr->length + 1) * sizeof(char));
    memcpy(data, bptr->data, bptr->length);
    data[bptr->length] = '\0';


    // printf("Extended key usage: %s\n", data);

    if (strstr(data, EKU_DEFAULT) == NULL) {
        return false;
        printf("Extended key usage FAILED\n\n");
    } else {
        return true;
        printf("Extended key usage PASSED\n\n");
    }
}


int validate_certificate(char *filename, char *domain_name) {

    BIO *certificate_bio = NULL;
    X509 *cert = NULL;

    //create BIO object to read certificate
    certificate_bio = BIO_new(BIO_s_file());

    //Read certificate into BIO
    if (!(BIO_read_filename(certificate_bio, filename)))
    {
        fprintf(stderr, "Error in reading cert BIO filename\n");
        exit(EXIT_FAILURE);
    }
    if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL)))
    {
        fprintf(stderr, "Error in loading certificate\n");
        exit(EXIT_FAILURE);
    }

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

    // Process input csv file.
    char *csv_file = argv[1];

    FILE *fp = fopen(csv_file, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open csv file\n");
        exit(EXIT_FAILURE);
    }

    //initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();


    char filename[MAX_LENGTH], domain[MAX_LENGTH];
    char line[MAX_LENGTH];

    // Parse all lines of csv file.
    while (fgets(line, MAX_LENGTH, fp) != NULL) {

        if (sscanf(line, "%[^,],%s\n", filename, domain) != 2) {
            fprintf(stderr, "Error reading in csv file\n");
            exit(EXIT_FAILURE);
        }

        //printf("Filename: %s\n", filename);
        //printf("Domain  : %s\n\n", domain);

        int result = validate_certificate(filename, domain);

        printf("%s,%s,%d\n", strstr(filename, "test"), domain, result);
    }

    fclose(fp);


    // Get output file ready for the dicking.
    FILE *fout = fopen("output.csv", "w");
    if (fout == NULL) {
        fprintf(stderr, "Error creating output file");
        exit(EXIT_FAILURE);
    }


    // Close the output file.
    fclose(fout);

    // Job done!
    exit(EXIT_SUCCESS);
}
