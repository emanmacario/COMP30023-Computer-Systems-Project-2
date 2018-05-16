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


#define MAX_LENGTH 1024
#define DATE_LEN 128
#define EXTNAME_LEN 1024

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


    char filename[MAX_LENGTH], domain[MAX_LENGTH];
    char buffer[MAX_LENGTH];

    while (fgets(buffer, MAX_LENGTH, fp) != NULL) {

        if (sscanf(buffer, "%[^,],%s\n", filename, domain) != 2) {
            fprintf(stderr, "Error reading in csv file\n");
            exit(EXIT_FAILURE);
        }

        printf("Filename: %s\n", filename);
        printf("Domain  : %s\n", domain);
    }

    fclose(fp);




    const char test_cert_example[] = "./sample_certs/testsix.crt";
    
    BIO *certificate_bio = NULL;
    X509 *cert = NULL;
    X509_NAME *cert_issuer = NULL;
    X509_CINF *cert_inf = NULL;
    STACK_OF(X509_EXTENSION) * ext_list;

    //initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    //create BIO object to read certificate
    certificate_bio = BIO_new(BIO_s_file());

    //Read certificate into BIO
    if (!(BIO_read_filename(certificate_bio, test_cert_example)))
    {
        fprintf(stderr, "Error in reading cert BIO filename");
        exit(EXIT_FAILURE);
    }
    if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL)))
    {
        fprintf(stderr, "Error in loading certificate");
        exit(EXIT_FAILURE);
    }

    print_certificate(cert);


    X509_NAME *subj = X509_get_subject_name(cert);
    for (int i = 0; i < X509_NAME_entry_count(subj); i++) {
        X509_NAME_ENTRY *e = X509_NAME_get_entry(subj, i);
        ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);
        char *str = ASN1_STRING_data(d);
        printf("%2d: %s\n", i, str);
    }

    ASN1_TIME *not_before = X509_get_notBefore(cert);
    ASN1_TIME *not_after = X509_get_notAfter(cert);


    char not_before_str[DATE_LEN];
    convert_ASN1_TIME(not_before, not_before_str, DATE_LEN);
    printf("\nNot before: %s\n", not_before_str);

    char not_after_str[DATE_LEN];
    convert_ASN1_TIME(not_after, not_after_str, DATE_LEN);
    printf("Not after: %s\n", not_after_str);


    // Check time differences. Either of pday or psec must be positive
    // for the certificate to still be valid. Need to check this for both
    // not before and not after dates.
    int pday, psec;
    ASN1_TIME_diff(&pday, &psec, not_before, NULL);

    printf("pday = %d\n", pday);
    printf("psec = %d\n", psec);

    
    ASN1_TIME_diff(&pday, &psec, NULL, not_after);
    printf("\npday = %d\n", pday);
    printf("psec = %d\n", psec);



    // Get size of public key in bits.
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    int key_type = EVP_PKEY_type(pkey->type);
    assert(key_type == EVP_PKEY_RSA);
    int keysize = BN_num_bits(pkey->pkey.rsa->n);
    EVP_PKEY_free(pkey);
    printf("Key size = %d bits\n", keysize);


    
    
    // Fucking around with extensions
    STACK_OF(X509_EXTENSION) *exts = cert->cert_info->extensions;

    int n_exts;
    if (exts) {
        n_exts = sk_X509_EXTENSION_num(exts);
    } else {
        n_exts = 0;
    }


    for (int i = 0; i < n_exts; i++) {
        X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);
        //IFNULL_FAIL(ex, "Error, unable to extract extension from stack");
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
        //IFNULL_FAIL(obj, "Error, unable to extract ASN1 object from extension");

        BIO *ext_bio = BIO_new(BIO_s_mem());
        //IFNULL_FAIL(ext_bio, "Unable to allocate memory for extension value BIO");
        if (!X509V3_EXT_print(ext_bio, ex, 0, 0)) {
            M_ASN1_OCTET_STRING_print(ext_bio, ex->value);
        }

        BUF_MEM *bptr;
        BIO_get_mem_ptr(ext_bio, &bptr);
        BIO_set_close(ext_bio, BIO_NOCLOSE);

        // remove newlines
        int lastchar = bptr->length;
        if (lastchar > 1 && (bptr->data[lastchar-1] == '\n' || bptr->data[lastchar-1] == '\r')) {
            bptr->data[lastchar-1] = (char) 0;
        }
        if (lastchar > 0 && (bptr->data[lastchar] == '\n' || bptr->data[lastchar] == '\r')) {
            bptr->data[lastchar] = (char) 0;
        }

        BIO_free(ext_bio);

        unsigned nid = OBJ_obj2nid(obj);
        if (nid == NID_undef) {
            // no lookup found for the provided OID so nid came back as undefined.
            char extname[EXTNAME_LEN];
            OBJ_obj2txt(extname, EXTNAME_LEN, (const ASN1_OBJECT *) obj, 1);
            printf("extension name is %s\n", extname);
        } else {
            // the OID translated to a NID which implies that the OID has a known sn/ln
            const char *c_ext_name = OBJ_nid2ln(nid);
            //IFNULL_FAIL(c_ext_name, "invalid X509v3 extension name");
            printf("extension name is %s\n", c_ext_name);
        }

        printf("extension length is %lu\n", bptr->length);
        printf("extension value is %s\n", bptr->data);

    }


    exit(EXIT_SUCCESS);
}









