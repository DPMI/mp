/**
 * This might seem a bit ugly, modifying argc and argv like this. But given the
 * alternatives this was a quick solution which turned out to work quite well.
 *
 * Rewrite it if you feel like it. I guess it would be more proper to translate
 * argv to configuration options (instead of the otherway around) because you
 * probably have more configuration options than CLI arguments anway.
 * 
 * I consider this a hack anyway.
 * -- David Sveningsson <dsv@bth.se> 2011-06-17
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "configfile.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

static const char* config_filename(int argc, char* argv[], const char* defname){
  for ( int i = 0; i < argc; i++ ){
    const char* cur = argv[i];

    if ( strncmp(cur, "--config", 8) != 0 ){
      continue;
    }
    if ( cur[8] == '=' ){ /* filename follows */
      return &cur[9];
    }
    if ( i+1 == argc || argv[i+1][0] == '-' ){ /* missing filename argument */
      fprintf(stderr, "Missing argument to --config\n");
      continue;
    }
    return argv[i+1];
  }
  return defname;
}

static char* trim(char* str){
  assert(str);

  /* leading */
  while ( isspace(str[0]) ){
    str++;
  }

  /* only whitespace */
  if ( str[0] == 0 ){
    return str;
  }

  /* trailing */
  char* ptr = str + strlen(str) - 1;
  while ( ptr > str && isspace(ptr[0]) ){
    ptr--;
  }
  *(ptr+1) = 0; /* ptr points to the last non-whitespace char */

  return str;
}

static void split_line(char* line, char** opt, char** optarg){
  assert(line);
  assert(opt);
  assert(optarg);

  char* ptr = strchr(line, '=');

  if ( !ptr ){ /* no argument provided */
    *opt = line;
    return;
  }

  *ptr = 0;
  *opt = trim(line);
  *optarg = trim(ptr+1);
}

/**
 * This function inserts CLI arguments at position i by reallocating the array
 * and shifting the arguments from position i N steps forward, then copying
 * the new arguments to the created slot.
 */
static int append_arg(int* argc, char** argv[], int i, const char* opt, const char* optarg){
  const int new_args = optarg ? 2 : 1; /* arguments to insert */
  const int orig_args = *argc;
  char** array = *argv; /* temporary to make code cleaner */

  /* allocate new argv array */
  array = realloc(array, sizeof(char*) * (orig_args + new_args));

  /* shift previous arguments */
  {

    /**
            ARRAY
        +--------------+
     0  | program_name |
        +--------------+
     1  |    --foo     | src   (given i=1)
        +--------------+
     2  | DEADC0DEDEAD |  
        +--------------+
     3  | DEADC0DEDEAD | dst   (given new_args=2)
        +--------------+
    ... >              <
        +--------------+
     N  |              |
        +--------------+
     */

    void* src = (void*)&array[i];
    void* dst = (void*)&array[i+new_args];
    size_t bytes = (void*)&array[orig_args] - src;
    memmove(dst, src, bytes);
  }

  /* yes it leaks memory. Once per string.
   * But WTH... OS will reclaim it and it is not a continious leak. */
  array[i] = strdup(opt);
  if ( optarg ){
    array[i+1] = strdup(optarg);
  }

  *argc = orig_args + new_args;
  *argv = array;
  return i + new_args;
}

/* Translation table for config options -> CLI arguments */
static struct translation_t {
  const char* name;
  const char* ref;
} translation[] = {
  {"MAnic", "--manic"},
  {"CI", "--interface"},
  {"LOCAL", "--local"},
  {NULL, NULL}
};

int parse_config(const char* filename, int* argc, char** argv[], struct option options[]){
  assert(filename);
  assert(argv);
  assert(options);

  static char buffer[256];

  /* count number of options */
  unsigned int noOptions = 0;
  struct option* ptr = options;
  while ( ptr->name ){
    noOptions++;
    ptr++;
  }

  /* allow filename to be overridden by --config */
  const char* _filename = config_filename(*argc, *argv, filename);

  FILE* fp = fopen(_filename, "r");
  if ( !fp ){
    int saved = errno;
    logmsg(stderr, "Failed to open configuration file \"%s\": %s\n", _filename, strerror(errno));
    return saved;
  }

  logmsg(stderr, "Reading configuration from \"%s\".\n", _filename);

  /* create a copy of argv since it is most likely not on the heap already */
  {
    int n = *argc;
    size_t bytes = sizeof(char*) * n;
    char** tmp = malloc(bytes);
    memcpy(tmp, *argv, bytes);
    *argv = tmp;
  }

  unsigned int linenum = 0;
  int i = 1;
  while( fgets(buffer, sizeof(buffer), fp) != NULL) {
    linenum++;
    char* line = trim(buffer);

    /* only comment */
    if( line[0] == '#' ) {
      continue;
    }

    /* empty line */
    if ( strlen(line) == 0 ){
      continue;
    }

    /* split line into option and argument */
    char* opt = NULL;
    char* optarg = NULL;
    split_line(line, &opt, &optarg);

    /* try to locate a translation */
    struct translation_t* cur = translation;
    while ( cur->name ){
      if ( strcmp(cur->name, opt) == 0 ){
	break;
      }
      cur++;
    }

    /* no matching argument */
    if ( !cur->name ){
      logmsg(stderr, "%s:%d: Unrecognized configuration option '%s`.\n", _filename, linenum, opt);
      continue;
    }

    /* insert these arguments */
    i = append_arg(argc, argv, i, cur->ref, optarg);

  } //while(fgets(line...

  fclose(fp);
  return 0;
}