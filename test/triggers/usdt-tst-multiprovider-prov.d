/*
 * Oracle Linux DTrace.
 * Copyright (c) 2024, Oracle and/or its affiliates. All rights reserved.
 * Licensed under the Universal Permissive License v 1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

/* @@skip: provider declaration - not a test */

provider prova { probe entrya(); };
provider provb { probe entryb(); probe entryc(int a, char *b) : (char * b, int a); };
provider provc { probe entryd(); };
